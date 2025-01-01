import { ReactNode } from 'react';

const TablePageContent = (
    {
        toolBar,
        pageNav,
        children
    }: {
        toolBar?: ReactNode,
        pageNav?: ReactNode,
        children?: ReactNode
    }
) => {
    return (
        <>
            {toolBar &&
                <div className="flex flex-row justify-start items-center w-full">
                    {toolBar}
                </div>
            }
            <div className="w-full overflow-auto">
                {children}
            </div>
            {pageNav &&
                <div className="flex flex-row justify-center items-center w-full">
                    {pageNav}
                </div>
            }
        </>
    )
}

export default TablePageContent;
