import { parse } from 'ts-command-line-args';

type ImageDownloadArgs = {
	listFile: string,
	scanName: string,
}

type SbomGenerationArgs = {
	imagesFile: string,
	suffix: string,
	generator: 'trivy' | 'syft'
}

/**
 * `${suffix}:${sbomsFile}`
 */
export type SbomFileList = `${string}:${string}`[] | undefined

type ScanAndPushArgs = {
	trivy: SbomFileList,
	grype: SbomFileList,
	dt: SbomFileList,
	scanSuffix: string
}

type EvaluateArgs = {
	resultFile: string,
	absolute: boolean
}

const parseGenrator = (value: any) => {
	if (typeof value !== 'string') {
		throw new Error('Invalid value for generator')
	}

	if (value !== 'trivy' && value !== 'syft') {
		throw new Error('Invalid value for generator')
	}

	return value
}

const parseSbomFileList = (value: any) => {
	if (typeof value !== 'string') {
		throw new Error('Invalid value for sbomFile')
	}

	const [suffix, sbomFile] = value.split(':')

	if (!suffix || !sbomFile) {
		console.log(suffix, sbomFile)
		throw new Error('Invalid value for sbomFile')
	}

	return `${suffix}:${sbomFile}` as const
}

export const commandLineParser = <T extends 'imageDownload' | 'sbomGeneration' | 'scanAndPush' | 'evaluate'>(command: T): T extends 'imageDownload' ? ImageDownloadArgs : T extends 'sbomGeneration' ? SbomGenerationArgs : T extends 'scanAndPush' ? ScanAndPushArgs : EvaluateArgs => {
	if (command === 'imageDownload') {
		return parse<ImageDownloadArgs>({
			listFile: { type: String },
			scanName: { type: String }
		}) as T extends 'imageDownload' ? ImageDownloadArgs : T extends 'sbomGeneration' ? SbomGenerationArgs : T extends 'scanAndPush' ? ScanAndPushArgs : EvaluateArgs
	}

	if (command === 'sbomGeneration') {
		return parse<SbomGenerationArgs>({
			imagesFile: { type: String },
			suffix: { type: String },
			generator: { type: parseGenrator }
		}) as T extends 'imageDownload' ? ImageDownloadArgs : T extends 'sbomGeneration' ? SbomGenerationArgs : T extends 'scanAndPush' ? ScanAndPushArgs : EvaluateArgs
	}

	if (command === 'scanAndPush') {
		return parse<ScanAndPushArgs>({
			trivy: { type: parseSbomFileList, multiple: true, optional: true },
			grype: { type: parseSbomFileList, multiple: true, optional: true },
			dt: { type: parseSbomFileList, multiple: true, optional: true },
			scanSuffix: { type: String }
		}) as T extends 'imageDownload' ? ImageDownloadArgs : T extends 'sbomGeneration' ? SbomGenerationArgs : T extends 'scanAndPush' ? ScanAndPushArgs : EvaluateArgs
	}

	return parse<EvaluateArgs>({
		resultFile: { type: String },
		absolute: { type: Boolean, alias: 'a' }
	}) as T extends 'imageDownload' ? ImageDownloadArgs : T extends 'sbomGeneration' ? SbomGenerationArgs : T extends 'scanAndPush' ? ScanAndPushArgs : EvaluateArgs
}