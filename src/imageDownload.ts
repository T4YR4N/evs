import runShellCommand from "./helper/runShellCommand"

// not used yet

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