import { FaExclamationCircle } from "react-icons/fa"

const CapacityViewer = ({ capacity, fields, currentWeek, withStaff }) => {
  return (
    <div className="columns is-gapless is-size-7 is-mobile">
      <div className="column is-narrow table-container has-text-right">
        <table className="table">
          <thead>
            <tr>
              <th className="is-dark">CAPACITY VIEW</th>
            </tr>
          </thead>
          <tfoot>
            <tr>
              <th className="is-dark">CAPACITY VIEW</th>
            </tr>
          </tfoot>
          <tbody>
            {fields &&
              fields
                .filter((field) => (withStaff ? 1 : field.order < 1000))
                .map((field) => (
                  <tr key={"weekly-header-row-" + field.internal}>
                    <th
                      key={"field-" + field.internal}
                      className={
                        field.type === "capacity"
                          ? "has-text-danger"
                          : field.type === "staffing"
                          ? "has-text-link"
                          : ""
                      }
                    >
                      {field.external + " ->"}
                    </th>
                  </tr>
                ))}
            <tr>
              <th className="has-text-link">{"Has Shrinkage? ->"}</th>
            </tr>
            <tr>
              <th className="has-text-link">{"Has Planned? ->"}</th>
            </tr>
            <tr>
              <th className="has-text-link">{"Has Actual? ->"}</th>
            </tr>
          </tbody>
        </table>
      </div>
      <div className="column table-container ml-1">
        <table className="table is-striped is-hoverable">
          <thead>
            <tr>
              {capacity &&
                capacity.map((weekly) => {
                  return (
                    <th
                      key={"weekly-head-" + weekly.week.code}
                      className={
                        weekly.week.code === currentWeek.code
                          ? "is-danger"
                          : "is-dark"
                      }
                      style={{ whiteSpace: "nowrap", cursor: "pointer" }}
                      title={weekly.Comment}
                    >
                      <div className="mx-auto">
                        {weekly.firstDate}
                        <FaExclamationCircle
                          className={`ml-1 ${
                            weekly.Comment ? "has-text-warning" : "is-hidden"
                          }`}
                        />
                      </div>
                    </th>
                  )
                })}
            </tr>
          </thead>
          <tfoot>
            <tr>
              {capacity &&
                capacity.map((weekly) => {
                  return (
                    <th
                      key={"weekly-foot-" + weekly.week.code}
                      className="is-dark"
                      style={{ whiteSpace: "nowrap" }}
                    >
                      {weekly.firstDate}
                    </th>
                  )
                })}
            </tr>
          </tfoot>
          <tbody>
            {fields &&
              fields
                .filter((field) => (withStaff ? 1 : field.order < 1000))
                .map((field) => (
                  <tr key={"weekly-body-row-" + field.internal}>
                    {capacity &&
                      capacity.map((weekly) => (
                        <td
                          key={
                            "weekly-body-" + weekly.week.code + field.internal
                          }
                          style={{ whiteSpace: "nowrap", textAlign: "center" }}
                        >
                          {weekly[field.internal] ? (
                            Math.round(weekly[field.internal] * 1000) / 1000
                          ) : weekly[field.internal] === 0 ? (
                            <span className="has-text-primary">0</span>
                          ) : (
                            <span className="has-text-light">#</span>
                          )}
                        </td>
                      ))}
                  </tr>
                ))}
            <tr>
              {capacity &&
                capacity.map((weekly) => (
                  <td
                    key={"weekly-body-" + weekly.week.code + "-has-shrinkage"}
                    style={{ whiteSpace: "nowrap", textAlign: "center" }}
                  >
                    {weekly["hasShrinkage"] ? (
                      <span
                        className="has-text-primary"
                        title={[
                          "mapping - code - percentage",
                          ...weekly.pShrinkage.map(
                            (row) =>
                              row.mapping +
                              " - " +
                              row.code +
                              " - " +
                              row.percentage
                          ),
                        ].join("\n")}
                      >
                        YES
                      </span>
                    ) : (
                      <span className="has-text-light">#</span>
                    )}
                  </td>
                ))}
            </tr>
            <tr>
              {capacity &&
                capacity.map((weekly) => (
                  <td
                    key={"weekly-body-" + weekly.week.code + "-has-planned"}
                    style={{ whiteSpace: "nowrap", textAlign: "center" }}
                  >
                    {weekly["hasPlanned"] ? (
                      <span
                        className="has-text-primary"
                        title={[
                          "channel - volumes - aht",
                          ...weekly.planned.map(
                            (row) =>
                              row.name + " - " + row.volumes + " - " + row.aht
                          ),
                        ].join("\n")}
                      >
                        YES
                      </span>
                    ) : (
                      <span className="has-text-light">#</span>
                    )}
                  </td>
                ))}
            </tr>
            <tr>
              {capacity &&
                capacity.map((weekly) => (
                  <td
                    key={"weekly-body-" + weekly.week.code + "-has-actual"}
                    style={{ whiteSpace: "nowrap", textAlign: "center" }}
                  >
                    {weekly["hasActual"] ? (
                      <span
                        className="has-text-primary"
                        title={[
                          "channel - volumes - aht",
                          ...weekly.actual.map(
                            (row) =>
                              row.name + " - " + row.volumes + " - " + row.aht
                          ),
                        ].join("\n")}
                      >
                        YES
                      </span>
                    ) : (
                      <span className="has-text-light">#</span>
                    )}
                  </td>
                ))}
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default CapacityViewer
