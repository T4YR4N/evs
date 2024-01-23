import fs from 'fs'
import runShellCommand from './helper/runShellCommand'

const getDigest = async ([image, tag]: [string, string]) => {
	const command = `docker manifest inspect ${image}:${tag} -v`
  
	const result = await runShellCommand(command)
  
	const digest = JSON
		.parse(result)
		.find((y: any) => y?.Descriptor?.platform?.architecture === 'arm64')
		?.Descriptor
		?.digest
  
	if (typeof digest !== 'string') {
	  	throw new Error(`No digest for image ${image}:${tag}`)
	}
  
	return digest
}
  
const generateSbom = async ([image, tag, digest]: [string, string, string]) => {
	const command = `syft docker:${image}@${digest} -o cyclonedx-json`

	const sbom = JSON.parse(await runShellCommand(command))
	sbom.metadata.tools = undefined // this has to be done to ensure trivy compatibility, as trivy errors when trying to parse the tools object

	fs.writeFileSync(`./sboms/${image}_${tag}.sbom.json`, JSON.stringify(sbom))

	return `./sboms/${image}_${tag}.sbom.json`
}

/**
 * Store format:
 * [ image, tag, digest, sbomPath, DT-info ]
 */
export type Store = [string, string, string, string, {uuid: string, token: string}|undefined][]

export const images:[string, string][] = [
	['alpine', '3.19'],
	['debian', 'bookworm'],
	['nginx', '1.25.3-alpine'],
	['python', '3.13.0a3-bookworm'],
	['redis', '7.2.4-alpine'],
	['node', '21-bullseye-slim'],
	['mariadb', '10.5.23-focal'],
	['openjdk', '23-ea-5-jdk-oraclelinux8'],
	['centos', 'centos7'],
	['ruby', '3.3.0-bookworm'],
	['amazonlinux', '2023'],
	['haproxy', '2.8.5'],
	['elasticsearch', '8.12.0'],
	['maven', '3.9.6-eclipse-temurin-11'],
	['buildpack-deps', 'bullseye-curl'],
	['vault', '1.11.11']
]

const main = async () => {
	const store = JSON.parse(fs.readFileSync('./store.json').toString()) as Store

	const newImages = images.filter(([image, tag]) => !store.find(([storedImage, storedTag, storedDigest, storedPath, dtInfo]) => storedImage === image && storedTag === tag && fs.existsSync(storedPath)))

	if (newImages.length === 0) {
		console.log('No new images')
		return
	}

	const newImagesMessage = `Found ${newImages.length} new images`
	const listNewImagesMessage = newImages.reduce((acc, curr) => `${acc}\n${curr[0]}:${curr[1]}`, 'New images:')

	console.log(newImagesMessage)
	console.log(listNewImagesMessage)

	const imagesWithDigests = await Promise.all(newImages.map(async (i) => {
		return [...i, await getDigest(i)] as const
	}))

	const imagesWithSbomPaths = await Promise.all(imagesWithDigests.map(async (i) => {
		return [...i, await generateSbom([...i])] as const
	}))

	const allImagesWithSbomPaths = [...store, ...imagesWithSbomPaths] as Store

	fs.writeFileSync('./store.json', JSON.stringify(allImagesWithSbomPaths))
}

main()