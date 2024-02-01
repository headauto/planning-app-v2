import { ObjectId } from "mongodb"
import { connectToDatabase } from "../../../../lib/mongodb"
import { verifySession, verifyPermissions, ROLES } from "../../../../lib/verification"

export default async function handler(req, res) {
	const { query, method, body, headers } = req

	console.log(headers)

	let payload = body.payload //{name, volumes, aht}

	let capPlanId = query.capPlan //"id"
	let weekCode = query.week //"YYYYw#"

	const { client, db } = await connectToDatabase()

	let verification = await verifySession(db, headers.authorization)

	if (method === "POST") {
		if (!capPlanId || !weekCode || !payload || !payload.name) {
			return res.status(400).json({
				message: `Undefined capPlan, week or channel name`,
				data: null,
			})
		}

		if (!(verification.verified && verifyPermissions(ROLES.MANAGER,null,db,headers.authorization))) {

			return res.status(401).json(verification)
		}

		let capPlan = await db
			.collection("capPlans")
			.findOne({ _id: ObjectId(capPlanId) })

		console.log("CapPlan:", capPlan)

		let channels = capPlan
			? capPlan.staffing
				? capPlan.staffing.channels
				: []
			: []

		console.log("Channels:", channels)

		if (!channels.length) {
			return res.status(406).json({
				message: `Invalid Cap Plan`,
				data: null,
			})
		}

		if (!channels.find((channel) => payload.name === channel.name)) {
			return res.status(406).json({
				message: `No such channel in Cap Plan`,
				data: null,
			})
		}

		let entry = await db
			.collection("capEntries")
			.findOne({ capPlan: capPlanId, week: weekCode })

		console.log(entry)

		let currentPlanned = []

		if (entry) {
			currentPlanned = entry.planned || []
		}

		let newPlanned = []
		console.log("FIRST", payload.name, currentPlanned)
		if (currentPlanned.length === 0) {
			newPlanned = [payload]
		} else if (!currentPlanned.find((item) => item.name === payload.name)) {
			console.log("APPENDED")
			newPlanned = [...currentPlanned, payload]
		} else {
			newPlanned = currentPlanned.map((channelPlanned) => {
				if (channelPlanned.name === payload.name) {
					return {
						name: payload.name,
						aht:
							payload.aht === "delete"
								? null
								: payload.aht || channelPlanned.aht,
						volumes:
							payload.volumes === "delete"
								? null
								: payload.volumes || channelPlanned.volumes,
					}
				} else {
					return channelPlanned
				}
			})
		}

		const update = {
			$set: {
				planned: newPlanned,
				lastUpdated: new Date(),
				updatedBy: verification.user.username,
				updateType: "planned",
			},
		}
		const options = { upsert: true }

		let response = await db
			.collection("capEntries")
			.updateOne({ capPlan: capPlanId, week: weekCode }, update, options)

		return res.status(200).json({
			message: `Updated Entry in Database!`,
			inserted: update,
			response: response,
		})
	} else {
		//BAD REQUEST
		return res
			.status(405)
			.json({ message: "Method not Allowed, use POST only" })
	}
}
