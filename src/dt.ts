export const apiKey = 'odt_NNPUOluZ9nFbCovZVAFicNovTFDDwTpp'
export const baseUrl = 'http://localhost:8081/api/v1'
export const constructDTUrl = (path: string) => `${baseUrl}/${path}`

export type DTFinding = {
	component: {
		uuid: string,
		name: string,
		version: string,
		purl: string,
		cpe: string,
		project: string
	},
	vulnerability: {
		uuid: string,
		source: string,
		vulnId: string,
		cvssV3BaseScore: number,
		severity: string,
		severityRank: number,
		epssScore: number,
		epssPercentile: number,
		cweId: number,
		cweName: string,
		cwes: unknown[],
		aliases: unknown[],
		description: string
		recommendation: unknown | null,
	},
	analysis: { isSuppressed: boolean },
	attribution: {
		analyzerIdentity: string,
		attributedOn: number
	},
	matrix: string
}

// 1. Create project
// 2. upload sbom
// 3. read results