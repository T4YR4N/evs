# Table of contents

[What is this?](#what-is-this)<br>
[Setup](#setup)<br>
[Scripts and how to use](#scripts-and-how-to-use)<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[generateSbom](#generatesbom)<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[scan](#scan)<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[evaluate](#evaluate)<br>
[What to do now with the results?](#what-to-do-now-with-the-results)

# What is this?

Maybe this will be helpful for some, maybe not. But i built it so i might as well share it.

The scripts provided by this repository are meant to be used to compare different vulnerability scanners, especially in the context of containers. Three different scanners are currently implemented:

- Grype
- Trivy
- DependencyTrack (if you want to call it a scanner)

Using the scripts provided, you can create SBOMs for a given set of docker images, utilizing two different SBOM generation tools for containers:

- Syft
- Trivy

You can then pass different sets of SBOMs to the different vulnerability scanners, for example to compare the results of Grype scans of Syft generated SBOMs with Grype scans of Trivy generated SBOMs.

You can the feed the results of these scans to the last script, to to some evaluations on the results. The last script is explicitly designed to be changed for different use cases, so you will have to modify it to fit your needs. You can read more in this process further down in this document. But in any case, to use this selection of scripts, you should know your way around TypeScript or JavaScript at the very least.

# Setup

The scripts are written in TypeScript and require a Node.js environment to run. The Node version used in development is `v20.11.1`.

To install the dependencies, run the following command:

```bash
npm install
```

If you want to use dependencyTrack, you will have to set up a [dependencyTrack instance](https://docs.dependencytrack.org/getting-started/deploy-docker/). Then you will have to create an [API Key](https://docs.dependencytrack.org/integrations/rest-api/). Then you will have to go to the `src/dt.ts` file and change the values in the `apiKey` and `baseUrl` constants to fit your setup. The current values are example values from one of my local testing instances.

And that's it! You're ready to run the scripts.

# Scripts and how to use

This section describes the scripts provided by this repository. Everytime you use these scripts you will have to prefix them with `npm run` to run them as they are npm scripts. In case you pass the arguments correctly and the scripts are not working as intended but throw an error, as if the arguments are not passed correctly, you might have to pass `--` as the first argument to the script like so:

```bash
npm run generateSbom -- --anyOtherArguments
```

But before you can start using the scripts, you will have to create a file that lists the images you want to scan. The file has to be a JSON file ending in `.images.json` and has to have the following structure:

```json
[
  {
    "image": "string",
    "tag": "string",
    "digest": "string",
    "imagePath": "string"
  },
  ...
]
```

For convenience, i recommend to store the images in a `./images` and setting up subdirectories for different sets of imags. For example `./images/alpineImages` and `./images/ubuntuImages`. The `imagePath` has to be the path to your tar archive of the image either absolute or relative to the project directory. The entire rest of the properties is required but purely informational. You could just use placeholders if you wanted to.

Having created this file, you can now start with the `generateSbom` script.

### `generateSbom`:

Arguments:

- imagesFile: string
- suffix: string
- generator: 'trivy' | 'syft'

The generateSbom script will generate SBOMs for the images listed in the images file. All SBOMs will be stored in the `./sboms` directory. A specific SBOM will be stored in `./sboms/{suffix}/{generator}/{image}_{tag}_{digestWithoutSha256}.sbom.json`
Therefore you can generate SBOMs for the same image with different tools and group them under the same directory.

The `suffix` argument is used to group the SBOMs under a common directory. The `generator` argument is used to determine which SBOM generator to use and also to save it to the correct directory. The imagesFile argument is the path to the imageFile previously described.

In return the script will create a file called `./{suffix}_{generator}.sboms.json` which lists all information from the input file and adds the path to the generated SBOMs.

### `scan`:

Arguments:

- trivy: SbomFileList
- grype: SbomFileList
- dt: SbomFileList
- scanSuffix: string

After generating the SBOMs, you can now scan them with the different scanners. This script will scan the SBOMs with the scanners and store the results in the `./results` directory. A specific result will be stored in `./results/{scanSuffix}/{scanner}/{image}_{tag}_{digestWithoutSha256}.result.json`.

The `trivy`, `grype` and `dt` arguments are paths to possibly different `.sboms.json` files generated by the `generateSbom` script. The SbomFileList type is defined as a string that is prefixed with a name for file you are passing after a colon. For example `trivy:./trivy_sboms.json`. The `scanSuffix` argument is used to group the results under a common directory.

For better understanding here is an example:

You previoulsy have generated SBOMs for the same images, once with syft and once with trivy. You used `--suffix=main` for the `generateSbom` command. Now you want to scan the both sets of SBOMs with trivy and with grype. Therefore your command would look like this:

```bash
npm run scan
  --
  --scanSuffix=compare_syft_and_trivy_sboms_with_grype_and_trivy
  --trivy=syftSboms./main_syft.sboms.json,trivySboms:./main_trivy.sboms.json
  --grype=syftSboms:./main_syft.sboms.json,trivySboms:./main_trivy.sboms.json
```

In return the script creates a file called `./{scanSuffix}.results.json` which lists all information from the input files and adds the path to the generated results. The exact definition can be found in the `src/types.ts` file as `type ResultFile`.

### `evaluate`:

Arguments:

- resultFile: string
- absolute: boolean

The evaluate script can be used to do everything you want with the results file. The script is supposed to be changed to fit your needs. The script will be passed the path to the `results.json` file generated previously. The `absolute` argument is used to determine if the returning values should be absolute or relative to the overall amount of matches found.

As a default behavior, the script will create an array with all matches found across all the results per image. The constant `amountOfUniqueMatches` is an array of numbers, which includes the amount of unique matches found in the results. A unique match is identified via it's vulnerability ID (CVE/GHSA/ELSA/...), the name of the package and it's version. In the end the script will log the amount of unique matches found per image, and the amount of matches found by each of the different scanners as JSON Arrays if you pass the `absoulte` argument. If you don't pass the `absolute` argument, the script will log the amount of matches per tool as a percentage of the total amount of matches found.

Now it's up to you what to do with the code.

# False positives

For false positive detection, i only looked at the matches that were only found by one tool. As soon as they were found by two or more tools i considered them to be correct. This is a very simple approach and might not be the best way to do it. But it's a start.

To do what i did, you will have to change the evaluate script to include something like the following:

```typescript
const trivyMatchesNotInGrype = trivyMatchesPerSuffix[0].matches.map(
  (x, index) => {
    const grypeMatches = grypeMatchesPerSuffix[0].matches[index];

    return x.filter(
      ({ cve, pkg }) =>
        grypeMatches.findIndex(
          ({ cve: grypeCve, pkg: grypePkg }) =>
            cve === grypeCve && pkg === grypePkg
        ) === -1
    );
  }
);

const grypeMatchesNotInTrivy = grypeMatchesPerSuffix[0].matches.map(
  (x, index) => {
    const trivyMatches = trivyMatchesPerSuffix[0].matches[index];

    return x.filter(
      ({ cve, pkg }) =>
        trivyMatches.findIndex(
          ({ cve: trivyCve, pkg: trivyPkg }) =>
            cve === trivyCve && pkg === trivyPkg
        ) === -1
    );
  }
);

const index = images.findIndex((x) => x.includes("selectedImageName"));

const logMatches = (matches: MappedResult["matches"]) => {
  matches.forEach(({ cve, pkg, matchType }) => {
    console.log(
      `${cve}			${pkg}${matchType ? "			" : ""}${matchType ? matchType : ""}`
    );
  });
};

console.log("trivy matches not in grype");
logMatches(trivyMatchesNotInGrype[index]);
console.log("");
console.log("grype matches not in trivy");
logMatches(grypeMatchesNotInTrivy[index]);
```

Here you can get the matches that were only found by one tool and log them. You select the image you want to look at by changing the `selectedImageName` string.

But if you want to look at false positives, it might be more usefull to look at [yardstick](https://github.com/anchore/yardstick) from anchore. They only support syft and grype but you might be able to integrate trivy as well. (Look at the `yardstick/src/yardstick/tool/grype.py` file to see how they integrated grype.)

# What to do now with the results?

Now that you are done with the evaluation, you can do whatever you want with the results. I put them in matlab diagrams to compare the different scanners.
