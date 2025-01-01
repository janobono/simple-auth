import { useContext, useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { PieChart, Settings, ShoppingCart, Tool } from 'react-feather';
import { containsAuthority } from '../../api/model';
import { Authority } from '../../api/model/data';
import { DialogContext } from '../../context';

import BaseDialog from '../dialog/base-dialog';
import WiwaButton from '../ui/wiwa-button';

const AuthoritiesDialog = ({dialogId, showDialog, authorities, okHandler, cancelHandler}: {
    dialogId: string,
    showDialog: boolean,
    authorities: Authority[],
    okHandler: (authorities: Authority[]) => void,
    cancelHandler: () => void
}) => {
    const dialogState = useContext(DialogContext);

    const [customerAuthority, setCustomerAuthority] = useState(false);
    const [employeeAuthority, setEmployeeAuthority] = useState(false);
    const [managerAuthority, setManagerAuthority] = useState(false);
    const [adminAuthority, setAdminAuthority] = useState(false);

    useEffect(() => {
        setCustomerAuthority(containsAuthority(authorities, Authority.CUSTOMER));
        setEmployeeAuthority(containsAuthority(authorities, Authority.EMPLOYEE));
        setManagerAuthority(containsAuthority(authorities, Authority.MANAGER));
        setAdminAuthority(containsAuthority(authorities, Authority.ADMIN));
    }, [showDialog, authorities]);

    return (!dialogState?.modalRoot ? null : createPortal(
        <BaseDialog id={dialogId} showDialog={showDialog} closeHandler={cancelHandler}>
            <div className="container p-2 mx-auto">
                <div className="flex flex-col items-center justify-center">
                    <div className="text-base xl:text-lg font-bold text-center">User authorities</div>
                    <form
                        className="max-w-sm"
                        onSubmit={(event => {
                            event.preventDefault();
                            const authorities = [];
                            if (customerAuthority) {
                                authorities.push(Authority.CUSTOMER);
                            }
                            if (employeeAuthority) {
                                authorities.push(Authority.EMPLOYEE);
                            }
                            if (managerAuthority) {
                                authorities.push(Authority.MANAGER);
                            }
                            if (adminAuthority) {
                                authorities.push(Authority.ADMIN);
                            }
                            okHandler(authorities as Authority[]);
                        })}>

                        <div className="w-full pt-2">
                            <div className="flex flex-row items-center gap-2">
                                <input
                                    type="checkbox"
                                    checked={customerAuthority}
                                    onChange={() => setCustomerAuthority(!customerAuthority)}
                                    className="checkbox sm:max-md:checkbox-sm md:max-lg:checkbox-sm lg:max-xl:checkbox-sm"
                                />
                                <ShoppingCart size="18"/>
                                <span>Customer</span>
                            </div>
                        </div>

                        <div className="w-full pt-2">
                            <div className="flex flex-row items-center gap-2">
                                <input
                                    type="checkbox"
                                    checked={employeeAuthority}
                                    onChange={() => setEmployeeAuthority(!employeeAuthority)}
                                    className="checkbox sm:max-md:checkbox-sm md:max-lg:checkbox-sm lg:max-xl:checkbox-sm"
                                />
                                <Tool size="18"/>
                                <span>Employee</span>
                            </div>
                        </div>

                        <div className="w-full pt-2">
                            <div className="flex flex-row items-center gap-2">
                                <input
                                    type="checkbox"
                                    checked={managerAuthority}
                                    onChange={() => setManagerAuthority(!managerAuthority)}
                                    className="checkbox sm:max-md:checkbox-sm md:max-lg:checkbox-sm lg:max-xl:checkbox-sm"
                                />
                                <PieChart size="18"/>
                                <span>Manager</span>
                            </div>
                        </div>

                        <div className="w-full pt-2">
                            <div className="flex flex-row items-center gap-2">
                                <input
                                    type="checkbox"
                                    checked={adminAuthority}
                                    onChange={() => setAdminAuthority(!adminAuthority)}
                                    className="checkbox sm:max-md:checkbox-sm md:max-lg:checkbox-sm lg:max-xl:checkbox-sm"
                                />
                                <Settings size="18"/>
                                <span>Admin</span>
                            </div>
                        </div>

                        <div className="join pt-2">
                            <WiwaButton
                                className="btn-primary join-item"
                                type="submit"
                            >Ok</WiwaButton>
                            <WiwaButton
                                className="btn-accent join-item"
                                onClick={() => {
                                    cancelHandler();
                                }}
                            >Cancel</WiwaButton>
                        </div>
                    </form>
                </div>
            </div>
        </BaseDialog>
        , dialogState.modalRoot))
}

export default AuthoritiesDialog;
