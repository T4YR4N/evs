import { writeArbitraryFile } from "../helper/fileHandler"
import runShellCommand from "../helper/runShellCommand"

const grypeScan = async (sbomPath: string, image: string, tag: string, digest: string, scanSuffix: string, suffix: string) => {
    const command = `grype --add-cpes-if-none -o json sbom:'${sbomPath}'`

    const result = await runShellCommand(command)

	const cwd = process.cwd()
	const digestWithoutSha256 = digest.replace('sha256:', '')
	const filePath = `${cwd}/results/${scanSuffix}/grype/${suffix}/${image}_${tag}_${digestWithoutSha256}.result.json` as const
    
	writeArbitraryFile(filePath, result)

    return filePath
}

export default grypeScan