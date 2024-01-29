const commandLineParser = () => {
	const arg = process.argv[2]

	if (arg === 'trivy') return arg
	if (arg === 'syft') return arg

	throw new Error('Invalid argument')
}

export default commandLineParser