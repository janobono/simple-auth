import { formatNumber } from '.';

const WiwaValueNumber = ({value}: { value?: number }) => {
    return (
        <span className="text-xs xl:text-sm">{formatNumber(value)}</span>
    )
}

export default WiwaValueNumber;
