import { formatBoolean } from '.';

const WiwaValueBoolean = ({value}: { value?: boolean }) => {
    return (
        <span className="text-xs xl:text-sm">{formatBoolean(value)}</span>
    )
}

export default WiwaValueBoolean;
