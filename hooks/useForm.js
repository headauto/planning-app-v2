/**
 * @props
 *
 * fields = [{name: STRING, default: ANY, required: BOOLEAN}, ...]
 * callback = function (form) => runs instead of resetAll()
 *
 **/

import { useEffect, useState, useReducer } from "react"

const useForm = ({ fields, callback }) => {
  const form = {}

  const [isReset, setIsReset] = useState(true)

  const reducer = (state, action) => {
    switch (action.type) {
      case "ADD_FIELD":
        return {
          ...state,
          [action.itemKey]: action.payload,
        }
      case "SET_FORM":
        return {
          ...action.payload,
        }
      case "UPDATE_FIELD":
        // console.log(action.id)
        // console.log(action.payload);
        // console.log(state);
        return {
          ...state,
          [action.id]: action.payload,
        }
      default:
        return state
    }
  }
  const [state, dispatch] = useReducer(reducer, form)

  const setup = () => {
    fields &&
      typeof fields === "object" &&
      fields.length &&
      fields.forEach((field) => {
        dispatch({
          type: "ADD_FIELD",
          payload: field.default,
          itemKey: field.name,
        })
      })
  }

  useEffect(() => {
    fields && (callback ? callback(form) : resetAll())
    setup()
  }, [])

  const set = async (fieldName, value) => {
    let found = fields.find((field) => field.name === fieldName)
    setIsReset(false)
    if (found) {
      dispatch({ type: "UPDATE_FIELD", id: fieldName, payload: value })
    } else {
      console.log("Field does not exist")
    }
  }

  const setMany = (formObj) => {
    //setForm(formObj)
    setIsReset(false)
    Object.entries(formObj).forEach((entry) => {
      dispatch({ type: "UPDATE_FIELD", id: entry[0], payload: entry[1] })
    })
  }

  const resetOne = async (fieldName) => {
    let found = fields.find((field) => fieldName === field.name)

    if (found) {
      dispatch({
        type: "UPDATE_FIELD",
        id: fieldName,
        payload: found.default,
      })
    } else {
      console.log("Field does not exist")
    }
  }

  const resetAll = () => {
    setIsReset(true)
    fields.forEach((field) => {
      dispatch({ type: "UPDATE_FIELD", id: field.name, payload: field.default })
    })
  }

  const getForm = () => {
    return state || ""
  }

  const get = (fieldName) => {
    return state[fieldName] || ""
  }

  const checkRequired = () => {
    let checked = true
    fields.forEach((field) => {
      checked = field.required ? (state[field.name] ? checked : false) : checked
    })
    return checked
  }

  const checkIsReset = () => {
    return isReset
  }

  return {
    getForm,
    get,
    set,
    setMany,
    resetOne,
    resetAll,
    checkRequired,
    checkIsReset,
  }
}

export default useForm
