import { PieChart, Settings, ShoppingCart, Tool, X } from 'react-feather';

import { containsAuthority } from '../../api/model';
import { Authority } from '../../api/model/data';

const WiwaUserAuthorities = ({authorities}: { authorities: Authority[] }) => {
    const admin = containsAuthority(authorities, Authority.ADMIN);
    const manager = containsAuthority(authorities, Authority.MANAGER);
    const employee = containsAuthority(authorities, Authority.EMPLOYEE);
    const customer = containsAuthority(authorities, Authority.CUSTOMER);

    return (
        <div className="grid grid-cols-4 gap-2 min-w-24">
            {admin ? <Settings size="18"/> : <X size="18"/>}
            {manager ? <PieChart size="18"/> : <X size="18"/>}
            {employee ? <Tool size="18"/> : <X size="18"/>}
            {customer ? <ShoppingCart size="18"/> : <X size="18"/>}
        </div>
    )
}

export default WiwaUserAuthorities;
