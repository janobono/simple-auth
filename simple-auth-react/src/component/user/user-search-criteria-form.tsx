import { useState } from 'react';
import { Search } from 'react-feather';
import { UserSearchCriteria } from '../../api/controller/user';
import WiwaButton from '../ui/wiwa-button';
import WiwaInput from '../ui/wiwa-input';

const UserSearchCriteriaForm = ({searchHandler}: {
    searchHandler: (criteria: UserSearchCriteria) => void
}) => {
    const [searchField, setSearchField] = useState<string>();

    return (
        <div className="flex flex-col w-full">
            <div className="join join-vertical md:join-horizontal w-full">
                <WiwaInput
                    className="join-item w-full"
                    placeholder="Email, first name or lastname"
                    value={searchField}
                    onChange={event => setSearchField(event.target.value)}
                    onKeyUp={(event) => {
                        if (event.key === 'Enter') {
                            searchHandler({searchField});
                        }
                    }}
                />
                <WiwaButton
                    title="Search"
                    className="join-item"
                    sizeClassName="btn-sm sm:max-md:btn-xs md:max-lg:btn-xs lg:max-xl:btn-xs"
                    onClick={() => searchHandler({searchField})}
                ><Search size={18}/></WiwaButton>
            </div>
        </div>
    )
}

export default UserSearchCriteriaForm;
