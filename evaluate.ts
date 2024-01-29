import fs from 'fs'
import { type GrypeResult, type TrivyResult } from './scan'
import type { Store } from './store'
import axios from 'axios'
import { DTFinding, constructDTUrl, apiKey } from './dt'
import {readStore} from './store'
import commandLineParser from './commandLineParser'

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

const readGrypeResult = (sbomPath: string) => {
	const result = fs.readFileSync(sbomPath).toString()
	return result
}

const readTrivyResult = (sbomPath: string) => {
	const result = fs.readFileSync(sbomPath).toString()
	return result
}

const readDTResult = async ([_, __, ___, ____, dtInfo]: Store[number]) => {
	if (!dtInfo) {
		throw new Error('No dtInfo')
	}

	const {uuid} = dtInfo

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

const main = async () => {
	const arg = commandLineParser()
	const images = readStore(arg)

	const grypeResults = images.map(([image, tag, digest, sbomPath]) => {
		const result = readGrypeResult(`./results_${arg}/grype/${image}_${tag}.json`)
		return mapGrypeResult(result)
	})

	const trivyResults = images.map(([image, tag, digest, sbomPath]) => {
		const result = readTrivyResult(`./results_${arg}/trivy/${image}_${tag}.json`)
		return mapTrivyResult(result)
	})

	const dtResults = await Promise.all(images.map(async ([image, tag, digest, sbomPath, dtInfo]) => {
		if (!dtInfo) {
			throw new Error(`No dtInfo for ${image}:${tag}`)
		}

		const result = await readDTResult([image, tag, digest, sbomPath, dtInfo])
		return mapDTResult(result)
	}))

	const overallAndPerToolFoundCvesPerImage = images.map(([image, tag, digest, sbomPath], index) => {
		const grypeCves = grypeResults[index].cves
		const trivyCves = trivyResults[index].cves
		const dtCves = dtResults[index].cves
		const {matches: grypeMatches} = grypeResults[index]
		const {matches: trivyMatches} = trivyResults[index]
		const {matches: dtMatches} = dtResults[index]

		const overallFoundCves = [...new Set([...grypeCves, ...trivyCves, ...dtCves])].length

		const grypeFoundCves = grypeCves.length
		const trivyFoundCves = trivyCves.length
		const dtFoundCves = dtCves.length
		const cvesFoundByDtAndNoOther = dtCves.filter((x) => !grypeCves.includes(x) && !trivyCves.includes(x)).length
		const cvesFoundByGrypeAndNoOther = grypeCves.filter((x) => !trivyCves.includes(x) && !dtCves.includes(x)).length
		const cvesFoundByTrivyAndNoOther = trivyCves.filter((x) => !grypeCves.includes(x) && !dtCves.includes(x)).length
		const matchesOnlyDTFound = dtMatches.filter((x) => !grypeMatches.find((y) => y.cve === x.cve && y.pkg === x.pkg) && !trivyMatches.find((y) => y.cve === x.cve && y.pkg === x.pkg)).length
		const matchesOnlyGrypeFound = grypeMatches.filter((x) => !trivyMatches.find((y) => y.cve === x.cve && y.pkg === x.pkg) && !dtMatches.find((y) => y.cve === x.cve && y.pkg === x.pkg)).length
		const matchesOnlyTrivyFound = trivyMatches.filter((x) => !grypeMatches.find((y) => y.cve === x.cve && y.pkg === x.pkg) && !dtMatches.find((y) => y.cve === x.cve && y.pkg === x.pkg)).length
		const overallMatches = [...grypeMatches, ...trivyMatches, ...dtMatches]
		const uniqueOverallMatches = overallMatches.reduce((acc, curr) => {
			const {cve, pkg} = curr

			const index = acc.findIndex((x) => x.cve === cve && x.pkg === pkg)

			if (index === -1) {
				acc.push({cve, pkg})
			}

			return acc
		}, [] as {cve: string, pkg: string}[]).length

		return {
			image,
			tag,
			overallFoundCves,
			grypeFoundCves,
			trivyFoundCves,
			dtFoundCves,
			cvesFoundByDtAndNoOther,
			cvesFoundByGrypeAndNoOther,
			cvesFoundByTrivyAndNoOther,
			matchesOnlyDTFound,
			matchesOnlyGrypeFound,
			matchesOnlyTrivyFound,
			uniqueOverallMatches,
			grypeMatches: grypeMatches.length,
			trivyMatches: trivyMatches.length,
			dtMatches: dtMatches.length
		}
	})

	const grypeData = overallAndPerToolFoundCvesPerImage.map((x) => (x.grypeMatches / x.uniqueOverallMatches) * 100)
	const trivyData = overallAndPerToolFoundCvesPerImage.map((x) => (x.trivyMatches / x.uniqueOverallMatches) * 100)
	const dtData = overallAndPerToolFoundCvesPerImage.map((x) => (x.dtMatches / x.uniqueOverallMatches) * 100)
	const all = overallAndPerToolFoundCvesPerImage.map((x) => 100)
	const labels = overallAndPerToolFoundCvesPerImage.map((x) => `${x.image}:${x.tag}`)
	
	console.log(`const grypeData = ${JSON.stringify(grypeData)}`)
	console.log(`const trivyData = ${JSON.stringify(trivyData)}`)
	console.log(`const dtData = ${JSON.stringify(dtData)}`)
	console.log(`const all = ${JSON.stringify(all)}`)
	console.log(`const labels = ${JSON.stringify(labels)}`)
}

main()