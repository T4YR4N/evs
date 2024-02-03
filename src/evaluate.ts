import axios from "axios"
import { apiKey, constructDTUrl } from "./dt"
import { ResultFile } from "./files"
import {commandLineParser} from "./helper/commandLineParser"
import { readResultFile } from "./helper/fileHandler"
import fs from 'fs'

export type MappedResult = {
	cves: string[],
	pkgPerCve: {cve: string, pkg: string[]}[],
	cvePerPkg: {pkg: string, cves: string[]}[],
	amountOfMatches: number,
	matches:{
		cve: string,
		pkg: string
	}[]
}

export interface GrypeResult {
	matches: {
		vulnerability: {
			id: string
		},
		artifact: {
			name: string,
			version: string
		}
	}[]
}

export interface TrivyResult {
	Results?: [{
		Vulnerabilities?: {
			VulnerabilityID: string,
			PkgName: string,
			InstalledVersion: string,
		}[]
	}]
}

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

const readDTResult = async (uuid: string) => {
	const findingGetResult = await axios.get<DTFinding[]>(constructDTUrl(`finding/project/${uuid}`), {
		headers: {
			'X-Api-Key': apiKey
		}
	})

	return findingGetResult.data
}

const mapGrypeResult = (result: string) => {
	const {matches} = JSON.parse(result) as GrypeResult
  	const mappedResult = matches.reduce((acc, curr) => {
    const  {cves, pkgPerCve, cvePerPkg, amountOfMatches, matches} = acc

    const cve = curr.vulnerability.id
    const version = curr.artifact.version
    const pkg = `${curr.artifact.name}@${version}`

    if (!cves.includes(cve)) {
      	cves.push(cve)
    }

    const pkgIndex = pkgPerCve.findIndex((x) => x.cve === cve)
    if (pkgIndex === -1) {
      	pkgPerCve.push({cve, pkg: [pkg]})
    } else {
      	pkgPerCve[pkgIndex].pkg.push(pkg)
    }

    const cveIndex = cvePerPkg.findIndex((x) => x.pkg === pkg)
    if (cveIndex === -1) {
      	cvePerPkg.push({pkg, cves: [cve]})
    } else {
      	cvePerPkg[cveIndex].cves.push(cve)
    }

    return {cves, pkgPerCve, cvePerPkg, amountOfMatches: amountOfMatches + 1, matches: [...matches, {cve, pkg}]}
},  {cves: [], pkgPerCve: [], cvePerPkg: [], amountOfMatches: 0, matches: []} as MappedResult)

  return mappedResult
}

const mapTrivyResult = (result: string) => {
	const parsedResult = JSON.parse(result) as TrivyResult

	const mappedResult = (parsedResult.Results?.[0]?.Vulnerabilities || []).reduce((acc, curr) => {
		const  {cves, pkgPerCve, cvePerPkg, amountOfMatches, matches} = acc

		const cve = curr.VulnerabilityID
		const version = curr.InstalledVersion
		const pkg = `${curr.PkgName}@${version}`

		if (!cves.includes(cve)) {
			cves.push(cve)
		}

		const pkgIndex = pkgPerCve.findIndex((x) => x.cve === cve)
		if (pkgIndex === -1) {
			pkgPerCve.push({cve, pkg: [pkg]})
		} else {
			pkgPerCve[pkgIndex].pkg.push(pkg)
		}

		const cveIndex = cvePerPkg.findIndex((x) => x.pkg === pkg)
		if (cveIndex === -1) {
			cvePerPkg.push({pkg, cves: [cve]})
		} else {
			cvePerPkg[cveIndex].cves.push(cve)
		}

		return {cves, pkgPerCve, cvePerPkg, amountOfMatches: amountOfMatches + 1, matches: [...matches, {cve, pkg}]}
	}, {cves: [], pkgPerCve: [], cvePerPkg: [], amountOfMatches: 0, matches: []} as MappedResult)

	return mappedResult
}

const mapDTResult = (result: DTFinding[]) => {
	const mappedResult = result.reduce((acc, curr) => {
		const {cves, pkgPerCve, cvePerPkg, amountOfMatches, matches} = acc

		const cve = curr.vulnerability.vulnId
		const version = curr.component.version
		const pkg = `${curr.component.name}@${version}`

		if (!cves.includes(cve)) {
			cves.push(cve)
		}

		const pkgIndex = pkgPerCve.findIndex((x) => x.cve === cve)
		if (pkgIndex === -1) {
			pkgPerCve.push({cve, pkg: [pkg]})
		} else {
			pkgPerCve[pkgIndex].pkg.push(pkg)
		}

		const cveIndex = cvePerPkg.findIndex((x) => x.pkg === pkg)
		if (cveIndex === -1) {
			cvePerPkg.push({pkg, cves: [cve]})
		} else {
			cvePerPkg[cveIndex].cves.push(cve)
		}

		return {cves, pkgPerCve, cvePerPkg, amountOfMatches: amountOfMatches + 1, matches: [...matches, {cve, pkg}]}
	},  {cves: [], pkgPerCve: [], cvePerPkg: [], amountOfMatches: 0, matches: []} as MappedResult)

	return mappedResult
}

const uniqueifyMatches = (macthes: MappedResult['matches']) => macthes.reduce((acc, curr) => {
	const {cve, pkg} = curr
	const index = acc.findIndex((x) => x.cve === cve && x.pkg === pkg)
	if (index === -1) {
		return [...acc, curr]
	}
	
	return acc
}, [] as MappedResult['matches'])

const main = async () => {
	const {resultFile: resultsFilePath, absolute} = commandLineParser('evaluate')
	const {trivy, grype, dt} = readResultFile(resultsFilePath)

	const mappedTrivyResults = trivy.map((trivyResults) => {
		const {suffix, results} = trivyResults
		const mappedResults = results.map((result) => {
			const {resultPath} = result
			const resultContent = fs.readFileSync(resultPath).toString()

			return {
				...result,
				mappedResult: mapTrivyResult(resultContent)
			}
		})
		return {
			suffix,
			results: mappedResults
		}
	})

	const mappedGrypeResults = grype.map((grypeResults) => {
		const {suffix, results} = grypeResults
		const mappedResults = results.map((result) => {
			const {resultPath} = result
			const resultContent = fs.readFileSync(resultPath).toString()

			return {
				...result,
				mappedResult: mapGrypeResult(resultContent)
			}
		})
		return {
			suffix,
			results: mappedResults
		}
	})

	const mappedDTResults = await Promise.all(dt.map(async (dtResults) => {
		const {suffix, results} = dtResults
		const mappedResults = results.map(async (result) => {
			const {resultUuid} = result
			const resultContent = await readDTResult(resultUuid)

			return {
				...result,
				mappedResult: mapDTResult(resultContent)
			}
		})
		return {
			suffix,
			results: await Promise.all(mappedResults)
		}
	}))

	const combinedResults = [...mappedTrivyResults, ...mappedGrypeResults, ...mappedDTResults]

	type UniqueMarkersPerImage = {
		image: string,
		tag: string,
		digest: string,
		imagePath: string,
		uniqueOverallMatches: MappedResult['matches'],
		uniqueOverallCves: string[]
	}[]

	const uniqueMarkersPerImage = combinedResults
		.reduce<UniqueMarkersPerImage>((acc, curr) => {
			const {results} = curr

			return results.map((result) => {
				const cvesOfResult = result.mappedResult.cves
				const macthesOfResult = result.mappedResult.matches

				const indexOfImage = acc.findIndex((x) => x.image === result.image && x.tag === result.tag && x.digest === result.digest && x.imagePath === result.imagePath)
				if (indexOfImage === -1) {
					return {
						image: result.image,
						tag: result.tag,
						digest: result.digest,
						imagePath: result.imagePath,
						uniqueOverallMatches: uniqueifyMatches(macthesOfResult),
						uniqueOverallCves: cvesOfResult
					}
				} else {
					const imageInAcc = acc[indexOfImage]
					return {
						...imageInAcc,
						uniqueOverallMatches: uniqueifyMatches([...imageInAcc.uniqueOverallMatches, ...macthesOfResult]),
						uniqueOverallCves: [...(new Set([...imageInAcc.uniqueOverallCves, ...cvesOfResult]))]
					}
				}
			})
		}, [] as UniqueMarkersPerImage)

	const amountOfUniqueMatches = uniqueMarkersPerImage.map(({uniqueOverallMatches}) => uniqueOverallMatches.length)
	const amountOfUniqueCves = uniqueMarkersPerImage.map(({uniqueOverallCves}) => uniqueOverallCves.length)
	const images = uniqueMarkersPerImage.map(({image, tag}) => `${image}:${tag}`)
	
	const trivyMatchesPerSuffix = mappedTrivyResults.map(({suffix, results}) => {
		return {
			suffix,
			matches: results.map(({mappedResult}) => mappedResult.matches)
		}
	})

	const grypeMatchesPerSuffix = mappedGrypeResults.map(({suffix, results}) => {
		return {
			suffix,
			matches: results.map(({mappedResult}) => mappedResult.matches)
		}
	})

	const dtMatchesPerSuffix = mappedDTResults.map(({suffix, results}) => {
		return {
			suffix,
			matches: results.map(({mappedResult}) => mappedResult.matches)
		}
	})

	const createChartJSDataset = (suffix: string, scanner: 'trivy' | 'grype' | 'DT' | undefined ,prepareData: () => number[]) => {
		const scannerColorMapper = {
			trivy: "red",
			grype: "blue",
			DT: "green"
		}

		return {
			label: scanner ? `${scanner} (${suffix})` : suffix,
			data: prepareData(),
			strokeColor: scanner ? scannerColorMapper[scanner] : "black",
			pointColor: scanner ? scannerColorMapper[scanner] : "black",
		}
	}

	const createChartJSData = (labels: string[], datasets: ReturnType<typeof createChartJSDataset>[]) => {
		return {
			labels,
			datasets
		}
	}


	if (absolute) {
		const all = createChartJSDataset('all', undefined, () => amountOfUniqueMatches)
		
		const trivyDatasets = trivyMatchesPerSuffix.map(({suffix, matches}) => {
			return createChartJSDataset(suffix, 'trivy', () => matches.map((x) => x.length))
		})

		const grypeDatasets = grypeMatchesPerSuffix.map(({suffix, matches}) => {
			return createChartJSDataset(suffix, 'grype', () => matches.map((x) => x.length))
		})

		const dtDatasets = dtMatchesPerSuffix.map(({suffix, matches}) => {
			return createChartJSDataset(suffix, 'DT', () => matches.map((x) => x.length))
		})

		console.log(`const data = ${JSON.stringify(createChartJSData(images, [...trivyDatasets, ...grypeDatasets, ...dtDatasets, all]))}`)
	} else {
		const all = createChartJSDataset('all', undefined, () => amountOfUniqueMatches.map(() => 100))

		const trivyDatasets = trivyMatchesPerSuffix.map(({suffix, matches}) => {
			return createChartJSDataset(suffix, 'trivy', () => matches.map((x, index) => x.length / amountOfUniqueMatches[index] * 100))
		})

		const grypeDatasets = grypeMatchesPerSuffix.map(({suffix, matches}) => {
			return createChartJSDataset(suffix, 'grype', () => matches.map((x, index) => x.length / amountOfUniqueMatches[index] * 100))
		})

		const dtDatasets = dtMatchesPerSuffix.map(({suffix, matches}) => {
			return createChartJSDataset(suffix, 'DT', () => matches.map((x, index) => x.length / amountOfUniqueMatches[index] * 100))
		})

		console.log(`const data = ${JSON.stringify(createChartJSData(images, [...trivyDatasets, ...grypeDatasets, ...dtDatasets, all]))}`)
	}
}

main()