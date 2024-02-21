import axios from "axios"
import { apiKey, constructDTUrl } from "../dt"
import fs from "fs"
import FormData from "form-data"

const pushToDependencyTrack = async (sbomPath: string, image: string, tag: string, digest: string, scanSuffix: string, suffix: string) => {
	const minProperties = {
		"name": `${image}:${tag}:${digest}_${scanSuffix}_${suffix}`,
		"classifier": "CONTAINER",
		"properties": [],
		"tags": [],
		"active": true
	}

	try {
		const projectPutResult = await axios.put(constructDTUrl('project'), minProperties, {
			headers: {
				'X-Api-Key': apiKey
			}
		})

		const uuid = projectPutResult.data.uuid as string

		if (!uuid) {
			throw new Error('No uuid')
		}

		const formData = new FormData()
		formData.append('project', uuid)
		const fileBuffer = fs.readFileSync(sbomPath)
		formData.append('bom', fileBuffer, {
			filename: `${image}_${tag}.sbom.json`,
			contentType: 'application/json'
		})

		const bomPostResult = await axios.post(constructDTUrl('bom'), formData, {
			headers: {
				'X-Api-Key': apiKey,
				'Content-Type': 'multipart/form-data',
			}
		})

		const token = bomPostResult.data.token as string

		if (!token) {
			throw new Error('No token')
		}

		return {
			uuid,
			token
		}
	} catch (err) {
		console.log(`Could not push to Dependency Track for ${image}:${tag}:${digest}_${suffix}`)
		console.log(err)
	}
}

export default pushToDependencyTrack