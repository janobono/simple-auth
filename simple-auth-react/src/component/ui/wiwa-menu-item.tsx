import { NavLink, To } from 'react-router-dom';
import { twMerge } from 'tailwind-merge';

const WiwaMenuItem = (
    {
        label,
        to,
        disabled = false,
    }: {
        label?: string,
        to: To,
        disabled?: boolean
    }) => {
    return (
        <li className={twMerge(`${disabled ? 'disabled' : ''}`)}>
            {disabled ?
                <span>{label}</span>
                :
                <NavLink className="text-xs xl:text-sm" to={to} end>{label}</NavLink>
            }
        </li>
    )
}

export default WiwaMenuItem;
