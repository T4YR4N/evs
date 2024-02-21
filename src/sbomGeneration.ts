import { commandLineParser } from "./helper/commandLineParser"
import { readImageFile, writeSbomFile, writeSbomsFile } from "./helper/fileHandler"
import runShellCommand from "./helper/runShellCommand"

const generateSbom = async (imagePath: string, generator: 'syft' | 'trivy', suffix: string, image: string, tag: string, digest: string) => {
	const syftCommand = `syft ${imagePath} -o cyclonedx-json`
	const trivyCommand = `trivy image --input ${imagePath} --format cyclonedx`

	const digestWithoutSha256 = digest.replace('sha256:', '')
	const cwd = process.cwd()
	const filePath = `${cwd}/sboms/${suffix}/${generator}/${image}_${tag}_${digestWithoutSha256}.sbom.json` as const

	if (generator === 'trivy') {
		const sbom = await runShellCommand(trivyCommand)

		writeSbomFile(filePath, sbom)

		return filePath
	}

	const sbom = JSON.parse(await runShellCommand(syftCommand))
	sbom.metadata.tools = undefined // this has to be done to ensure trivy compatibility, as trivy errors when trying to parse the tools object

	writeSbomFile(filePath, JSON.stringify(sbom))

	return filePath
}

const main = async () => {
	const args = commandLineParser('sbomGeneration')
	const images = readImageFile(args.imagesFile)

	const imagesWithSbomPaths = await Promise.all(images.map(async (image) => {
		const sbomPath = await generateSbom(image.imagePath, args.generator, args.suffix, image.image, image.tag, image.digest)

		return { ...image, sbomPath }
	}))

	writeSbomsFile(`${args.suffix}_${args.generator}.sboms.json`, imagesWithSbomPaths)
}

main()