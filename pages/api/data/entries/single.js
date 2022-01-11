/**
query: 
*/

import { connectToDatabase } from "../../../../lib/mongodb"
import { ObjectId } from "mongodb"
import { verifySession } from "../../../../lib/verification"

export default async function handler(req, res) {
  const { query, method, body, headers } = req

  console.log(headers)

  let payload = body.payload

  const { client, db } = await connectToDatabase()

  let verification = await verifySession(db, headers.authorization)

  if (method === "POST") {
    if (verification.verified && verification.permission <= 2) {
      if (payload) {
        let id = payload._id
        delete payload._id
        const update = { $set: payload }
        const options = { upsert: true }
        let response = await db
          .collection("capEntries")
          .updateOne(id ? { _id: ObjectId(id) } : {}, update, options)
        res.status(200).json({
          message: `Updated Entry in Database!`,
          inserted: payload,
          response: response,
        })
      } else {
        res.status(200).json({
          message: `Nothing to Update!`,
          data: null,
        })
      }
    } else {
      res.status(401).json(verification)
    }
  } else {
    //BAD REQUEST
    res.status(405).json({ message: "Method not Allowed, use POST only" })
  }
}
