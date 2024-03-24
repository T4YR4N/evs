/**
 * `${image}:${tag}`[]
 */
export type ListFile = `${string}:${string}`[];

/**
 * imagePath: `/images/${suffix}/${image}_${tag}_${digest (without 'sha256:')}.tar`
 */
export type ImagesFile = {
  image: string;
  tag: string;
  digest: string;
  imagePath: string;
}[];

/**
 * imagePath: `/images/${suffix}/${image}_${tag}_${digest (without 'sha256:')}.tar`\
 * sbomPath: `${cwd}/sboms/${suffix}/${trivy or syft}/${image}_${tag}_${digest (without 'sha256:')}.sbom.json`
 */
export type SbomsFile = (ImagesFile[number] & {
  sbomPath:
    | `${string}/sboms/${string}/syft/${string}_${string}_${string}.sbom.json`
    | `${string}/sboms/${string}/trivy/${string}_${string}_${string}.sbom.json`;
})[];

/**
 * imagePath: `/images/${suffix}/${image}_${tag}_${digest (without 'sha256:')}.tar`\
 * sbomPath: `${cwd}/sboms/${suffix}/${trivy or syft}/${image}_${tag}_${digest (without 'sha256:')}.sbom.json`\
 * resultPath: `${cwd}/results/${scanSuffix}/${trivy or grype}/${suffix}/${image}_${tag}_${digest (without 'sha256:')}.result.json`
 * resultUuid: uuid returned from Dependency-Track
 */
export type ResultFile = {
  trivy: {
    suffix: string;
    results: (SbomsFile[number] & {
      resultPath: `${string}/results/${string}/trivy/${string}/${string}_${string}_${string}.result.json`;
    })[];
  }[];
  grype: {
    suffix: string;
    results: (SbomsFile[number] & {
      resultPath: `${string}/results/${string}/grype/${string}/${string}_${string}_${string}.result.json`;
    })[];
  }[];
  dt: {
    suffix: string;
    results: (SbomsFile[number] & {
      resultUuid: string;
    })[];
  }[];
};
