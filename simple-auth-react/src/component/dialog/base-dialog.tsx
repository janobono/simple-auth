import type { ReactNode } from 'react';

const BaseDialog = (
    {
        id,
        showDialog,
        maxWidth = false,
        closeHandler,
        children
    }: {
        id: string,
        showDialog: boolean,
        maxWidth?: boolean,
        closeHandler?: () => void,
        children?: ReactNode
    }) => {
    return (
        <dialog id={id} className={showDialog ? 'modal modal-open' : 'modal'}>
            <div className={maxWidth ? 'modal-box w-11/12 max-w-full' : 'modal-box'}>{children}</div>
            <div
                className="modal-backdrop"
                onClick={() => {
                    if (closeHandler) {
                        closeHandler();
                    }
                }}/>
        </dialog>
    )
}

export default BaseDialog;
