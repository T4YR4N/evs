import { ResultFile, SbomsFile } from "./files";
import { SbomFileList, commandLineParser } from "./helper/commandLineParser";
import { readSbomsFile, writeResultFile } from "./helper/fileHandler";
import pushToDependencyTrack from "./scanner/dt";
import grypeScan from "./scanner/grype";
import trivyScan from "./scanner/trivy";

const deconstructSbomFileList = (sbomFileList: SbomFileList) => {
  if (!sbomFileList) {
    return [];
  }

  return sbomFileList
    .map((value) => {
      const [suffix, sbomsFile] = value.split(":");

      if (!suffix || !sbomsFile) {
        throw new Error(
          'Invalid value for sbomFile. Must be in the format "suffix:sbomsFile"'
        );
      }

      return { suffix, sbomsFile };
    })
    .map(({ suffix, sbomsFile }) => ({
      suffix,
      sbomsFile: readSbomsFile(sbomsFile),
    }));
};

const allSbomsFilesAreGeneratedFromSameImages = (sbomsFiles: SbomsFile[]) => {
  const imagesToCheckFor = sbomsFiles[0].map((sbomsFile) => ({
    image: sbomsFile.image,
    tag: sbomsFile.tag,
    digest: sbomsFile.digest,
    imagePath: sbomsFile.imagePath,
  }));

  return sbomsFiles.every((sbomsFile) => {
    const everyImageIsInImagesToCheckFor = sbomsFile.every((sbomsFile) => {
      return imagesToCheckFor.some((imageToCheckFor) => {
        return (
          imageToCheckFor.image === sbomsFile.image &&
          imageToCheckFor.tag === sbomsFile.tag &&
          imageToCheckFor.digest === sbomsFile.digest &&
          imageToCheckFor.imagePath === sbomsFile.imagePath
        );
      });
    });

    return everyImageIsInImagesToCheckFor;
  });
};

const main = async () => {
  const {
    trivy: toScanWithTrivy,
    grype: toScanWithGrype,
    dt: toScanWithDt,
    scanSuffix,
  } = commandLineParser("scanAndPush");

  const trivySbomsFiles = deconstructSbomFileList(toScanWithTrivy);
  const grypeSbomsFiles = deconstructSbomFileList(toScanWithGrype);
  const dtSbomsFiles = deconstructSbomFileList(toScanWithDt);

  if (
    !trivySbomsFiles.length &&
    !grypeSbomsFiles.length &&
    !dtSbomsFiles.length
  ) {
    console.log("No scans to perform");
    return;
  }

  if (
    !allSbomsFilesAreGeneratedFromSameImages([
      ...trivySbomsFiles.map((val) => val.sbomsFile),
      ...grypeSbomsFiles.map((val) => val.sbomsFile),
      ...dtSbomsFiles.map((val) => val.sbomsFile),
    ])
  ) {
    console.log("All sboms files must be generated from the same images");
    return;
  }

  const trivyResult: ResultFile["trivy"] = await Promise.all(
    deconstructSbomFileList(toScanWithTrivy).map(
      async ({ suffix, sbomsFile }) => {
        const results = await Promise.all(
          sbomsFile.map(async (x) => {
            const resultPath = await trivyScan(
              x.sbomPath,
              x.image,
              x.tag,
              x.digest,
              scanSuffix,
              suffix
            );

            return {
              ...x,
              resultPath,
            };
          })
        );

        return {
          suffix,
          results,
        };
      }
    )
  );

  const grypeResult: ResultFile["grype"] = await Promise.all(
    deconstructSbomFileList(toScanWithGrype).map(
      async ({ suffix, sbomsFile }) => {
        const results = await Promise.all(
          sbomsFile.map(async (x) => {
            const resultPath = await grypeScan(
              x.sbomPath,
              x.image,
              x.tag,
              x.digest,
              scanSuffix,
              suffix
            );

            return {
              ...x,
              resultPath,
            };
          })
        );

        return {
          suffix,
          results,
        };
      }
    )
  );

  const dtResult: ResultFile["dt"] = await Promise.all(
    deconstructSbomFileList(toScanWithDt).map(async ({ suffix, sbomsFile }) => {
      const results = await Promise.all(
        sbomsFile.map(async (x) => {
          const r = await pushToDependencyTrack(
            x.sbomPath,
            x.image,
            x.tag,
            x.digest,
            scanSuffix,
            suffix
          );

          if (!r) {
            throw new Error(
              `Could not push to Dependency Track for ${x.image}:${x.tag}:${x.digest}_${suffix}`
            );
          }

          return {
            ...x,
            resultUuid: r.uuid,
          };
        })
      );

      return {
        suffix,
        results,
      };
    })
  );

  const result: ResultFile = {
    trivy: trivyResult,
    grype: grypeResult,
    dt: dtResult,
  };

  writeResultFile(`${scanSuffix}.results.json`, result);
};

main();
