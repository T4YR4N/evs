import path from "path"
import runShellCommand from "../helper/runShellCommand"
import fs from "fs"

const trivyScan = async (sbomPath: string, image: string, tag: string, digest: string, scanSuffix: string, suffix: string) => {
	const cwd = process.cwd()
	const digestWithoutSha256 = digest.replace('sha256:', '')
	const filePath = `${cwd}/results/${scanSuffix}/trivy/${suffix}/${image}_${tag}_${digestWithoutSha256}.result.json` as const

	const directoryPath = path.dirname(filePath);

	if (!fs.existsSync(directoryPath)) {
		console.log(`Creating directory: ${directoryPath}`)
		fs.mkdirSync(directoryPath, { recursive: true })
	}

	const command = `trivy sbom '${sbomPath}' --format json --output '${filePath}'`

	await runShellCommand(command)

	return filePath
}

export default trivyScan