import { connectToDatabase } from "../../../lib/mongodb"
import { authorizeReportingRead } from "../../../lib/reportingAuthentication"
import {
  ROLES,
  verifyPermissions,
  verifySession,
} from "../../../lib/verification"

const ALLOWED_COLLECTIONS = new Set([
  "countries",
  "projects",
  "lobs",
  "capPlans",
  "languages",
  "weeks",
  "fields",
  "dow",
  "hours",
  "pms",
])

const REPORTING_COLLECTIONS = new Set([
  "capPlans",
  "weeks",
  "countries",
  "projects",
  "lobs",
  "languages",
])

const isReportingRequest = (selected) =>
  selected.length > 0 &&
  selected.every((collectionName) =>
    REPORTING_COLLECTIONS.has(collectionName)
  )

const parseBooleanParameter = (value) => {
  if (value === undefined) {
    return {
      valid: true,
      value: null,
    }
  }

  if (
    typeof value !== "string" ||
    !["true", "false"].includes(
      value.toLowerCase()
    )
  ) {
    return {
      valid: false,
      value: null,
    }
  }

  return {
    valid: true,
    value: value.toLowerCase() === "true",
  }
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", ["GET"])

    return res.status(405).json({
      message: "Method not allowed. Use GET only.",
      data: null,
    })
  }

  const selectedParameter = req.query.selected

  if (
    typeof selectedParameter !== "string" ||
    selectedParameter.trim() === ""
  ) {
    return res.status(400).json({
      message:
        "At least one structure must be selected.",
      data: null,
    })
  }

  const selected = [
    ...new Set(
      selectedParameter
        .split(",")
        .map((collectionName) =>
          collectionName.trim()
        )
        .filter(Boolean)
    ),
  ]

  if (
    selected.length === 0 ||
    selected.length >
      ALLOWED_COLLECTIONS.size
  ) {
    return res.status(400).json({
      message:
        " selected structures are invalid.",
      data: null,
    })
  }

  const invalidCollections = selected.filter(
    (collectionName) =>
      !ALLOWED_COLLECTIONS.has(collectionName)
  )

  if (invalidCollections.length > 0) {
    return res.status(403).json({
      message:
        "One or more selected structures are not available.",
      data: null,
    })
  }

  const activeParameter =
    parseBooleanParameter(req.query.active)

  if (!activeParameter.valid) {
    return res.status(400).json({
      message:
        " active parameter must be true or false.",
      data: null,
    })
  }

  if (
    activeParameter.value !== null &&
    !selected.includes("capPlans")
  ) {
    return res.status(400).json({
      message:
        " active parameter can only be used when capPlans is selected.",
      data: null,
    })
  }

  try {
    const { db } = await connectToDatabase()

    if (isReportingRequest(selected)) {
      const authorization =
        await authorizeReportingRead(db, req)

      if (!authorization.authorized) {
        return res
          .status(authorization.status)
          .json({
            message: authorization.message,
            data: null,
          })
      }
    } else {
      const verification = await verifySession(
        db,
        req.headers.authorization
      )

      if (!verification.verified) {
        return res.status(401).json({
          message:
            "A valid session is required.",
          data: null,
        })
      }

      const hasPermission =
        await verifyPermissions(
          ROLES.GUEST,
          verification.user
        )

      if (!hasPermission) {
        return res.status(403).json({
          message:
            "You do not have permission to access this resource.",
          data: null,
        })
      }
    }

    const output = {}

    for (const collectionName of selected) {
      const collectionFilter =
        collectionName === "capPlans" &&
        activeParameter.value !== null
          ? {
              active: activeParameter.value,
            }
          : {}

      output[collectionName] = await db
        .collection(collectionName)
        .find(collectionFilter)
        .sort({ name: 1 })
        .toArray()
    }

    res.setHeader(
      "Cache-Control",
      "no-store, max-age=0"
    )

    return res.status(200).json({
      message:
        "Retrieved selected structures.",
      data: output,
    })
  } catch (error) {
    console.error(
      "Structure retrieval failed:",
      error
    )

    return res.status(500).json({
      message:
        "Unable to retrieve structures.",
      data: null,
    })
  }
}
