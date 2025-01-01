import { To } from 'react-router-dom';
import WiwaMenuItem from './wiwa-menu-item';

export interface BreadcrumbData {
    key: number,
    label: string,
    to?: To
}

const WiwaBreadcrumb = ({breadcrumbs}: { breadcrumbs: BreadcrumbData[] }) => {
    return (
        <div className="flex w-full">
            <div className="text-xs xl:text-sm breadcrumbs">
                <ul>
                    {breadcrumbs.map(item =>
                        <WiwaMenuItem
                            key={item.key}
                            label={item.label} to={item.to || ''}
                            disabled={item.to === undefined}
                        />
                    )}
                </ul>
            </div>
        </div>
    )
}

export default WiwaBreadcrumb;
