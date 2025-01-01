import { ReactNode, useEffect, useState } from 'react';
import { createPortal } from 'react-dom';

import { DialogContext, } from '../../';
import BaseDialog from '../../../component/dialog/base-dialog';
import WiwaButton from '../../../component/ui/wiwa-button';
import { DialogAnswer, DialogData, DialogType } from '../../model/dialog';

const DIALOG_ID = 'dialog-state-provider-dialog-001';

const DialogProvider = ({children}: { children: ReactNode }) => {

    const [data, setData] = useState<DialogData>();
    const [show, setShow] = useState(false);
    const [modalRoot, setModalRoot] = useState<HTMLElement | null>(null);

    useEffect(() => {
        setModalRoot(document.getElementById('modal-root'));
    }, []);

    const showDialog = (data: DialogData) => {
        setData(data);
        setShow(true);
    }

    return (
        <>
            <DialogContext.Provider
                value={
                    {
                        modalRoot,
                        showDialog
                    }
                }
            >{children}
            </DialogContext.Provider>
            {modalRoot !== null && createPortal(
                <BaseDialog
                    id={DIALOG_ID}
                    showDialog={show}
                >
                    <div className="container p-2 mx-auto">
                        <div className="flex flex-col items-center justify-center">
                            {data?.title &&
                                <h1 className="text-base xl:text-lg font-bold text-center">
                                    {data.title}
                                </h1>
                            }
                            {data?.message &&
                                <p className="text-xs xl:text-sm text-center py-2 xl:py-5">
                                    {data.message}
                                </p>
                            }

                            {data?.type && data.type !== DialogType.OK_CANCEL && data.type !== DialogType.YES_NO &&
                                <WiwaButton
                                    className="btn-primary"
                                    onClick={() => {
                                        setShow(false);
                                        data.callback(DialogAnswer.OK);
                                    }}
                                >Ok</WiwaButton>
                            }

                            {data?.type && data.type === DialogType.OK_CANCEL &&
                                <div className="join">
                                    <WiwaButton
                                        className="btn-primary join-item"
                                        onClick={() => {
                                            setShow(false);
                                            data.callback(DialogAnswer.OK);
                                        }}
                                    >Ok</WiwaButton>
                                    <WiwaButton
                                        className="btn-accent join-item"
                                        onClick={() => {
                                            setShow(false);
                                            data.callback(DialogAnswer.CANCEL);
                                        }}
                                    >Cancel</WiwaButton>
                                </div>
                            }

                            {data?.type && data.type === DialogType.YES_NO &&
                                <div className="join">
                                    <WiwaButton
                                        className="btn-primary join-item"
                                        onClick={() => {
                                            setShow(false);
                                            data.callback(DialogAnswer.YES);
                                        }}
                                    >Yes</WiwaButton>
                                    <WiwaButton
                                        className="btn-accent join-item"
                                        onClick={() => {
                                            setShow(false);
                                            data.callback(DialogAnswer.NO);
                                        }}
                                    >No</WiwaButton>
                                </div>
                            }
                        </div>
                    </div>
                </BaseDialog>
                , modalRoot)
            }
        </>
    )
}

export default DialogProvider;
