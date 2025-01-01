const WiwaFormError = ({formError}: { formError?: string }) => {
    return (
        <>
            {formError &&
                <label className="label">
                    <span className="label-text-alt text-xs xl:text-sm text-error">{formError}</span>
                </label>
            }
        </>
    )
}

export default WiwaFormError;
