export enum DialogType {
    INFO, OK_CANCEL, YES_NO
}

export enum DialogAnswer {
    OK, CANCEL, YES, NO
}

export interface DialogData {
    type: DialogType,
    title?: string,
    message?: string,
    callback: (answer: DialogAnswer) => void
}

export interface DialogState {
    modalRoot: HTMLElement | null,
    showDialog: (data: DialogData) => void
}
