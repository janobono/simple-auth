import { ReactNode } from 'react';

const WiwaTable = <F, R>(
    {
        fields,
        tableHeaderColumn,
        rows,
        tableRowKey,
        tableRowColumn,
        actions,
        onRowSelected
    }: {
        fields: F[],
        tableHeaderColumn: (field: F) => ReactNode,
        rows?: R[],
        tableRowKey: (row: R) => string,
        tableRowColumn: (field: F, row: R) => ReactNode,
        actions?: (row: R) => ReactNode
        onRowSelected?: (row: R) => void
    }) => {

    const headRow = (
        <tr>
            {fields?.map(field => tableHeaderColumn(field))}
            {actions && <th></th>}
        </tr>
    );

    const dataRows = (
        <>
            {rows?.map(row =>
                <tr key={tableRowKey(row)} onClick={() => {
                    if (onRowSelected) {
                        onRowSelected(row);
                    }
                }}>
                    {fields?.map(field => tableRowColumn(field, row))}
                    {actions && actions(row)}
                </tr>
            )}
        </>
    );

    return (
        <table className="table table-zebra table-xs xl:table-sm">
            <thead>
            {headRow}
            </thead>
            <tbody>
            {dataRows}
            </tbody>
        </table>
    )
}

export default WiwaTable;
