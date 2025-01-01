import { ChevronLeft, ChevronRight } from 'react-feather';

import WiwaButton from './wiwa-button';

const WiwaPageable = (
    {
        isPrevious,
        previousHandler,
        page,
        pageHandler,
        isNext,
        nextHandler,
        disabled = false
    }: {
        isPrevious: boolean,
        previousHandler: () => void,
        page: number,
        pageHandler: () => void,
        isNext: boolean,
        nextHandler: () => void,
        disabled?: boolean
    }) => {
    return (
        <div className="join">
            <WiwaButton
                className="join-item"
                title="Predchádzajúca"
                disabled={disabled || !isPrevious}
                onClick={previousHandler}
            ><ChevronLeft size={18}/>
            </WiwaButton>
            <WiwaButton
                className="join-item"
                disabled={disabled}
                onClick={pageHandler}
            ><span>Stránka </span>{page}</WiwaButton>
            <WiwaButton
                className="join-item"
                title="Nasledujúca"
                disabled={disabled || !isNext}
                onClick={nextHandler}
            ><ChevronRight size={18}/>
            </WiwaButton>
        </div>
    )
}

export default WiwaPageable;
