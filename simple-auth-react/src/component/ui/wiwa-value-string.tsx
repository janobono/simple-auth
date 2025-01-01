const WiwaValueString = ({value}: { value?: string }) => {
    return (
        <span className="text-xs xl:text-sm">{value ? value : ''}</span>
    )
}

export default WiwaValueString;
