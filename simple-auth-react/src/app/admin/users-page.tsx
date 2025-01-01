import { useContext, useEffect, useState } from 'react';
import { Lock, Trash, Unlock, UserCheck, Users as FeatherUsers, UserX } from 'react-feather';
import { User } from '../../api/model/data';

import TablePageContent from '../../component/layout/table-page-content.tsx';
import WiwaBreadcrumb from '../../component/ui/wiwa-breadcrumb';
import WiwaButton from '../../component/ui/wiwa-button';
import WiwaPageable from '../../component/ui/wiwa-pageable';
import WiwaTable from '../../component/ui/wiwa-table.tsx';
import WiwaUserAuthorities from '../../component/ui/wiwa-user-authorities';
import WiwaValueBoolean from '../../component/ui/wiwa-value-boolean';
import WiwaValueNumber from '../../component/ui/wiwa-value-number';
import WiwaValueString from '../../component/ui/wiwa-value-string';
import AuthoritiesDialog from '../../component/user/authorities-dialog';
import UserProvider, { UserContext } from '../../component/user/user-provider';
import UserSearchCriteriaForm from '../../component/user/user-search-criteria-form';
import { DialogContext } from '../../context';
import { DialogAnswer, DialogType } from '../../context/model/dialog';

const AUTHORITIES_DIALOG_ID = 'admin-authorities-dialog-001';

const UsersPage = () => {
    return (
        <>
            <WiwaBreadcrumb breadcrumbs={[
                {key: 0, label: 'Admin'},
                {
                    key: 1,
                    label: 'Users',
                    to: '/admin/users'
                }
            ]}/>
            <UserProvider>
                <UsersPageContent/>
            </UserProvider>
        </>
    )
}

export default UsersPage;

const UsersPageContent = () => {
    const dialogState = useContext(DialogContext);
    const userState = useContext(UserContext);

    const [selected, setSelected] = useState<User>();
    const [showDialog, setShowDialog] = useState(false);

    useEffect(() => {
        userState?.getUsers().then();
    }, []);

    return (
        <>
            <TablePageContent
                toolBar={
                    <UserSearchCriteriaForm searchHandler={(criteria) => userState?.setCriteria(criteria)}/>
                }
                pageNav={
                    <WiwaPageable
                        isPrevious={userState?.previous || false}
                        previousHandler={() => userState?.setPage(userState?.page - 1)}
                        page={(userState?.page || 0) + 1}
                        pageHandler={() => userState?.getUsers()}
                        isNext={userState?.next || false}
                        nextHandler={() => userState?.setPage(userState?.page + 1)}
                        disabled={userState?.busy}
                    />
                }
            >
                <div className="h-[350px] xl:h-[500px] w-full">
                    <WiwaTable
                        fields={['id', 'email', 'firstName', 'lastName', 'confirmed', 'enabled', 'authorities']}
                        tableHeaderColumn={(field) => {
                            switch (field) {
                                case 'id':
                                    return (<th key={field}><WiwaValueString value="Id"/></th>);
                                case 'email':
                                    return (<th key={field}><WiwaValueString value="Email"/></th>);
                                case 'firstName':
                                    return (<th key={field}><WiwaValueString value="First Name"/></th>);
                                case 'lastName':
                                    return (<th key={field}><WiwaValueString value="Last Name"/></th>);
                                case 'confirmed':
                                    return (<th key={field}><WiwaValueString value="Confirmed"/></th>);
                                case 'enabled':
                                    return (<th key={field}><WiwaValueString value="Enabled"/></th>);
                                case 'authorities':
                                    return (<th key={field}><WiwaValueString value="Authorities"/></th>);
                            }
                        }}
                        rows={userState?.data}
                        tableRowKey={(row) => `${row.id}`}
                        tableRowColumn={(field, row) => {
                            switch (field) {
                                case 'id':
                                    return (<td key={field}><WiwaValueNumber value={row.id}/></td>);
                                case 'email':
                                    return (<td key={field}><WiwaValueString value={row.email}/></td>);
                                case 'firstName':
                                    return (<td key={field}><WiwaValueString value={row.firstName}/></td>);
                                case 'lastName':
                                    return (<td key={field}><WiwaValueString value={row.lastName}/></td>);
                                case 'authorities':
                                    return (
                                        <td key={field}>
                                            <div className="flex flex-row justify-start items-center gap-2">
                                                <WiwaButton
                                                    title="Set authorities"
                                                    className="btn-primary"
                                                    sizeClassName="btn-sm sm:max-md:btn-xs md:max-lg:btn-xs lg:max-xl:btn-xs"
                                                    disabled={userState?.busy || !userState?.isEditEnabled(row)}
                                                    onClick={() => {
                                                        setSelected(row);
                                                        setShowDialog(true);
                                                    }}
                                                >
                                                    <FeatherUsers size={18}/>
                                                </WiwaButton>
                                                <WiwaUserAuthorities authorities={row.authorities || []}/>
                                            </div>
                                        </td>
                                    );
                                case 'confirmed':
                                    return (
                                        <td key={field}>
                                            <div className="flex flex-row justify-start items-center gap-2">
                                                <WiwaButton
                                                    className="btn-warning"
                                                    sizeClassName="btn-sm sm:max-md:btn-xs md:max-lg:btn-xs lg:max-xl:btn-xs"
                                                    title={row.confirmed ? 'Disable confirmation' : 'Confirm'}
                                                    disabled={userState?.busy || !userState?.isEditEnabled(row)}
                                                    onClick={() => {
                                                        dialogState?.showDialog({
                                                            type: DialogType.YES_NO,
                                                            title: row.confirmed ? 'Disable confirmation' : 'Confirm',
                                                            message: row.confirmed ?
                                                                'Are you sure you want to disable confirmation of this user?' :
                                                                'Are you sure you want to confirm this user?',
                                                            callback: (answer: DialogAnswer) => {
                                                                if (answer === DialogAnswer.YES) {
                                                                    userState?.setConfirmed(row.id || 0, !row?.confirmed).then();
                                                                }
                                                            }
                                                        });
                                                    }}
                                                >
                                                    {row.confirmed ?
                                                        <UserX size={18}/>
                                                        :
                                                        <UserCheck size={18}/>
                                                    }
                                                </WiwaButton>
                                                <WiwaValueBoolean value={row.confirmed}/>
                                            </div>
                                        </td>
                                    );
                                case 'enabled':
                                    return (
                                        <td key={field}>
                                            <div className="flex flex-row justify-start items-center gap-2">
                                                <WiwaButton
                                                    className="btn-error"
                                                    sizeClassName="btn-sm sm:max-md:btn-xs md:max-lg:btn-xs lg:max-xl:btn-xs"
                                                    title={row.enabled ? 'Disable' : 'Enable'}
                                                    disabled={userState?.busy || !userState?.isEditEnabled(row)}
                                                    onClick={() => {
                                                        dialogState?.showDialog({
                                                            type: DialogType.YES_NO,
                                                            title: row.enabled ? 'Disable user' : 'Enable user',
                                                            message: row.enabled ?
                                                                'Are you sure you want to disable this user?' :
                                                                'Are you sure you want to enable this user?',
                                                            callback: (answer: DialogAnswer) => {
                                                                if (answer === DialogAnswer.YES) {
                                                                    userState?.setEnabled(row.id || 0, !row.enabled).then();
                                                                }
                                                            }
                                                        });
                                                    }}
                                                >
                                                    {row.enabled ?
                                                        <Lock size={18}/>
                                                        :
                                                        <Unlock size={18}/>
                                                    }
                                                </WiwaButton>
                                                <WiwaValueBoolean value={row.enabled}/>
                                            </div>
                                        </td>
                                    );
                            }
                        }}
                        actions={(row) =>
                            <td>
                                <WiwaButton
                                    className="btn-accent"
                                    sizeClassName="btn-sm sm:max-md:btn-xs md:max-lg:btn-xs lg:max-xl:btn-xs"
                                    title="Delete"
                                    disabled={userState?.busy || !userState?.isEditEnabled(row)}
                                    onClick={() => {
                                        dialogState?.showDialog({
                                            type: DialogType.YES_NO,
                                            title: 'Delete user',
                                            message: 'Are you sure you want to delete this user?',
                                            callback: (answer: DialogAnswer) => {
                                                if (answer === DialogAnswer.YES) {
                                                    userState?.deleteUser(row.id || 0).then();
                                                }
                                            }
                                        });
                                    }}
                                ><Trash size={18}/>
                                </WiwaButton>
                            </td>
                        }
                    />
                </div>
            </TablePageContent>

            <AuthoritiesDialog
                dialogId={AUTHORITIES_DIALOG_ID}
                showDialog={showDialog}
                authorities={selected?.authorities || []}
                cancelHandler={() => setShowDialog(false)}
                okHandler={(authorities) => {
                    if (selected && selected.id) {
                        userState?.setAuthorities(selected.id, authorities).then();
                    }
                    setShowDialog(false);
                    setSelected(undefined);
                }}/>
        </>
    )
}
