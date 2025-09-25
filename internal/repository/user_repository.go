package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/janobono/go-util/common"
	db2 "github.com/janobono/go-util/db"
	"github.com/janobono/simple-auth/simple-auth-service/generated/sqlc"
	"github.com/janobono/simple-auth/simple-auth-service/internal/db"
)

type UserRepository interface {
	AddUser(ctx context.Context, data *UserData) (*User, error)
	AddUserWithAttributesAndAuthorities(ctx context.Context, userData *UserData, userAttributes []*UserAttribute, userAuthorities []*Authority) (*User, error)
	CountById(ctx context.Context, id pgtype.UUID) (int64, error)
	CountByEmail(ctx context.Context, email string) (int64, error)
	CountByEmailAndNotId(ctx context.Context, email string, id pgtype.UUID) (int64, error)
	DeleteAll(ctx context.Context) error
	DeleteUserById(ctx context.Context, id pgtype.UUID) error
	GetUserAttributes(ctx context.Context, userID pgtype.UUID) ([]*UserAttribute, error)
	GetUserAuthorities(ctx context.Context, userID pgtype.UUID) ([]*Authority, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserById(ctx context.Context, id pgtype.UUID) (*User, error)
	SearchUsers(ctx context.Context, criteria *SearchUsersCriteria, pageable *common.Pageable) (*common.Page[*User], error)
	SetUserAttributes(ctx context.Context, data *UserAttributesData) ([]*UserAttribute, error)
	SetUserAuthorities(ctx context.Context, data *UserAuthoritiesData) ([]*Authority, error)
	SetUserConfirmed(ctx context.Context, userID pgtype.UUID, confirmed bool) (*User, error)
	SetUserEmail(ctx context.Context, userID pgtype.UUID, email string) (*User, error)
	SetUserEnabled(ctx context.Context, userID pgtype.UUID, enabled bool) (*User, error)
	SetUserPassword(ctx context.Context, userID pgtype.UUID, password string) (*User, error)
}

type userRepositoryImpl struct {
	dataSource *db.DataSource
}

func NewUserRepository(dataSource *db.DataSource) UserRepository {
	return &userRepositoryImpl{dataSource}
}

func (u *userRepositoryImpl) AddUser(ctx context.Context, data *UserData) (*User, error) {
	user, err := u.dataSource.Queries.AddUser(ctx, sqlc.AddUserParams{
		ID:        db2.NewUUID(),
		CreatedAt: db2.NowUTC(),
		Email:     data.Email,
		Password:  data.Password,
		Enabled:   data.Enabled,
		Confirmed: data.Confirmed,
	})
	if err != nil {
		return nil, err
	}
	return toUser(&user), nil
}

func (u *userRepositoryImpl) AddUserWithAttributesAndAuthorities(ctx context.Context, userData *UserData, userAttributes []*UserAttribute, userAuthorities []*Authority) (*User, error) {
	user, err := u.dataSource.ExecTx(ctx, func(q *sqlc.Queries) (interface{}, error) {
		user, err := q.AddUser(ctx, sqlc.AddUserParams{
			ID:        db2.NewUUID(),
			CreatedAt: db2.NowUTC(),
			Email:     userData.Email,
			Password:  userData.Password,
			Enabled:   userData.Enabled,
			Confirmed: userData.Confirmed,
		})
		if err != nil {
			return nil, err
		}

		for _, attribute := range userAttributes {
			if err := q.AddUserAttribute(ctx, sqlc.AddUserAttributeParams{
				UserID:      user.ID,
				AttributeID: attribute.Attribute.ID,
				Value:       attribute.Value,
			}); err != nil {
				return nil, err
			}
		}

		for _, authority := range userAuthorities {
			if err := q.AddUserAuthority(ctx, sqlc.AddUserAuthorityParams{
				UserID:      user.ID,
				AuthorityID: authority.ID,
			}); err != nil {
				return nil, err
			}
		}

		return &user, nil
	})
	if err != nil {
		return nil, err
	}
	return toUser(user.(*sqlc.User)), nil
}

func (u *userRepositoryImpl) CountById(ctx context.Context, id pgtype.UUID) (int64, error) {
	return u.dataSource.Queries.CountUsersById(ctx, id)
}

func (u *userRepositoryImpl) CountByEmail(ctx context.Context, email string) (int64, error) {
	return u.dataSource.Queries.CountUsersByEmail(ctx, email)
}

func (u *userRepositoryImpl) CountByEmailAndNotId(ctx context.Context, email string, id pgtype.UUID) (int64, error) {
	return u.dataSource.Queries.CountUsersByEmailNotId(ctx, sqlc.CountUsersByEmailNotIdParams{
		Email: email,
		ID:    id,
	})
}

func (u *userRepositoryImpl) DeleteAll(ctx context.Context) error {
	return u.dataSource.Queries.TruncateTableUser(ctx)
}

func (u *userRepositoryImpl) DeleteUserById(ctx context.Context, id pgtype.UUID) error {
	return u.dataSource.Queries.DeleteUserById(ctx, id)
}

func (u *userRepositoryImpl) GetUserAttributes(ctx context.Context, userID pgtype.UUID) ([]*UserAttribute, error) {
	var result []*UserAttribute
	userAttributes, err := u.dataSource.Queries.GetUserAttributes(ctx, userID)
	if err != nil {
		return result, err
	}
	for _, ua := range userAttributes {
		result = append(result, toUserAttribute(&ua))
	}
	return result, nil
}

func (u *userRepositoryImpl) GetUserAuthorities(ctx context.Context, userID pgtype.UUID) ([]*Authority, error) {
	var result []*Authority
	userAuthorities, err := u.dataSource.Queries.GetUserAuthorities(ctx, userID)
	if err != nil {
		return result, err
	}
	for _, au := range userAuthorities {
		result = append(result, toAuthority(&au))
	}
	return result, nil
}

func (u *userRepositoryImpl) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user, err := u.dataSource.Queries.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return toUser(&user), nil
}

func (u *userRepositoryImpl) GetUserById(ctx context.Context, id pgtype.UUID) (*User, error) {
	user, err := u.dataSource.Queries.GetUserById(ctx, id)
	if err != nil {
		return nil, err
	}
	return toUser(&user), nil
}

func (u *userRepositoryImpl) SearchUsers(ctx context.Context, criteria *SearchUsersCriteria, pageable *common.Pageable) (*common.Page[*User], error) {
	if criteria == nil {
		return nil, ErrNilCriteria
	}
	if pageable == nil {
		return nil, ErrNilPageable
	}

	totalRows, err := u.countUsers(ctx, criteria)
	if err != nil {
		return nil, err
	}

	content, err := u.searchUsers(ctx, criteria, pageable)
	if err != nil {
		return nil, err
	}

	return common.NewPage[*User](pageable, totalRows, content), nil
}

func (u *userRepositoryImpl) SetUserAttributes(ctx context.Context, data *UserAttributesData) ([]*UserAttribute, error) {
	_, err := u.dataSource.ExecTx(ctx, func(q *sqlc.Queries) (interface{}, error) {
		if err := q.DeleteUserAttributes(ctx, data.UserID); err != nil {
			return nil, err
		}
		for _, attribute := range data.Attributes {
			if err := q.AddUserAttribute(ctx, sqlc.AddUserAttributeParams{
				UserID:      data.UserID,
				AttributeID: attribute.Attribute.ID,
				Value:       attribute.Value,
			}); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return data.Attributes, nil
}

func (u *userRepositoryImpl) SetUserAuthorities(ctx context.Context, data *UserAuthoritiesData) ([]*Authority, error) {
	_, err := u.dataSource.ExecTx(ctx, func(q *sqlc.Queries) (interface{}, error) {
		if err := q.DeleteUserAuthorities(ctx, data.UserID); err != nil {
			return nil, err
		}
		for _, authority := range data.Authorities {
			if err := q.AddUserAuthority(ctx, sqlc.AddUserAuthorityParams{
				UserID:      data.UserID,
				AuthorityID: authority.ID,
			}); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return data.Authorities, nil
}

func (u *userRepositoryImpl) SetUserConfirmed(ctx context.Context, userID pgtype.UUID, confirmed bool) (*User, error) {
	user, err := u.dataSource.Queries.SetUserConfirmed(ctx, sqlc.SetUserConfirmedParams{
		ID:        userID,
		Confirmed: confirmed,
	})
	if err != nil {
		return nil, err
	}
	return toUser(&user), nil
}

func (u *userRepositoryImpl) SetUserEmail(ctx context.Context, userID pgtype.UUID, email string) (*User, error) {
	user, err := u.dataSource.Queries.SetUserEmail(ctx, sqlc.SetUserEmailParams{
		ID:    userID,
		Email: email,
	})
	if err != nil {
		return nil, err
	}
	return toUser(&user), nil
}

func (u *userRepositoryImpl) SetUserEnabled(ctx context.Context, userID pgtype.UUID, enabled bool) (*User, error) {
	user, err := u.dataSource.Queries.SetUserEnabled(ctx, sqlc.SetUserEnabledParams{
		ID:      userID,
		Enabled: enabled,
	})
	if err != nil {
		return nil, err
	}
	return toUser(&user), nil
}

func (u *userRepositoryImpl) SetUserPassword(ctx context.Context, userID pgtype.UUID, password string) (*User, error) {
	user, err := u.dataSource.Queries.SetUserPassword(ctx, sqlc.SetUserPasswordParams{
		ID:       userID,
		Password: password,
	})
	if err != nil {
		return nil, err
	}
	return toUser(&user), nil
}

func (u *userRepositoryImpl) countUsers(ctx context.Context, criteria *SearchUsersCriteria) (int64, error) {
	if criteria == nil {
		return 0, ErrNilCriteria
	}

	var query strings.Builder
	query.WriteString(`select count(*) from "user" u`)

	paramIndex := 1
	joins, conditions, parameters := u.buildSearchQueryParts(criteria, &paramIndex)
	query.WriteString(joins)

	if len(conditions) > 0 {
		query.WriteString(" where ")
		query.WriteString(strings.Join(conditions, " and "))
	}

	row := u.dataSource.Pool.QueryRow(ctx, query.String(), parameters...)
	var count int64
	err := row.Scan(&count)
	return count, err
}

func (u *userRepositoryImpl) searchUsers(ctx context.Context, criteria *SearchUsersCriteria, pageable *common.Pageable) ([]*User, error) {
	if criteria == nil {
		return nil, ErrNilCriteria
	}
	if pageable == nil {
		return nil, ErrNilPageable
	}

	var query strings.Builder
	query.WriteString(`select u.id, u.created_at, u.email, u.password, u.confirmed, u.enabled from "user" u`)

	paramIndex := 1
	joins, conditions, parameters := u.buildSearchQueryParts(criteria, &paramIndex)
	query.WriteString(joins)

	if len(conditions) > 0 {
		query.WriteString(" where ")
		query.WriteString(strings.Join(conditions, " and "))
	}

	query.WriteString(" order by " + u.safeOrder(pageable.Sort))
	query.WriteString(fmt.Sprintf(" limit %d offset %d", pageable.Limit(), pageable.Offset()))

	rows, err := u.dataSource.Pool.Query(ctx, query.String(), parameters...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var content []*User
	for rows.Next() {
		var user sqlc.User
		if err := rows.Scan(
			&user.ID,
			&user.CreatedAt,
			&user.Email,
			&user.Password,
			&user.Confirmed,
			&user.Enabled,
		); err != nil {
			return nil, err
		}
		content = append(content, toUser(&user))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return content, nil
}

func (u *userRepositoryImpl) buildSearchQueryParts(criteria *SearchUsersCriteria, paramIndex *int) (string, []string, []interface{}) {
	var joinBuilder strings.Builder
	var conditions []string
	var parameters []interface{}

	if cond, params := u.buildEmailConditions(criteria.Email, paramIndex); cond != "" {
		conditions = append(conditions, cond)
		parameters = append(parameters, params...)
	}

	if searchFieldJoins, cond, params := u.buildSearchFieldConditions(criteria.SearchField, criteria.AttributeKeys, paramIndex); cond != "" {
		joinBuilder.WriteString(searchFieldJoins)
		conditions = append(conditions, cond)
		parameters = append(parameters, params...)
	}

	if authorityJoins, cond, params := u.buildAuthoritiesConditions(criteria.Authorities, paramIndex); cond != "" {
		joinBuilder.WriteString(authorityJoins)
		conditions = append(conditions, cond)
		parameters = append(parameters, params...)
	}

	return joinBuilder.String(), conditions, parameters
}

func (u *userRepositoryImpl) buildEmailConditions(email string, paramIndex *int) (string, []interface{}) {
	if common.IsBlank(email) {
		return "", nil
	}
	cond := fmt.Sprintf("u.email like $%d", *paramIndex)
	param := "%" + common.ToScDf(email) + "%"
	*paramIndex++
	return cond, []interface{}{param}
}

func (u *userRepositoryImpl) buildSearchFieldConditions(searchField string, attributeKeys []string, paramIndex *int) (string, string, []interface{}) {
	values := common.SplitWithoutBlank(common.ToScDf(searchField), " ")
	if len(values) == 0 {
		return "", "", nil
	}

	var joins strings.Builder
	var conditions []string
	var parameters []interface{}

	if cond, params := u.buildSearchFieldEmailConditions(values, paramIndex); cond != "" {
		conditions = append(conditions, cond)
		parameters = append(parameters, params...)
	}

	if attributeJoins, cond, params := u.buildSearchFieldAttributeConditions(values, attributeKeys, paramIndex); cond != "" {
		joins.WriteString(attributeJoins)
		conditions = append(conditions, cond)
		parameters = append(parameters, params...)
	}

	return joins.String(), strings.Join(conditions, " or "), parameters
}

func (u *userRepositoryImpl) buildAuthoritiesConditions(authorities []string, paramIndex *int) (string, string, []interface{}) {
	clean := common.Deduplicate(common.FilterBlank(authorities))
	if len(clean) == 0 {
		return "", "", nil
	}

	var joins strings.Builder
	joins.WriteString(`
join user_authority ua on ua.user_id = u.id
join authority r on r.id = ua.authority_id
`)

	var condBuilder strings.Builder
	params := make([]interface{}, 0, len(clean))

	condBuilder.WriteString("(")
	for i, auth := range clean {
		if i > 0 {
			condBuilder.WriteString(" or ")
		}
		condBuilder.WriteString(fmt.Sprintf("r.authority = $%d", *paramIndex))
		params = append(params, auth)
		*paramIndex++
	}
	condBuilder.WriteString(")")

	return joins.String(), condBuilder.String(), params
}

func (u *userRepositoryImpl) buildSearchFieldEmailConditions(values []string, paramIndex *int) (string, []interface{}) {
	var sb strings.Builder
	params := make([]interface{}, 0, len(values))

	sb.WriteString("(")
	for i, val := range values {
		if i > 0 {
			sb.WriteString(" or ")
		}
		sb.WriteString(fmt.Sprintf("u.email like $%d", *paramIndex))
		params = append(params, "%"+val+"%")
		*paramIndex++
	}
	sb.WriteString(")")

	return sb.String(), params
}

func (u *userRepositoryImpl) buildSearchFieldAttributeConditions(values, attributeKeys []string, paramIndex *int) (string, string, []interface{}) {
	var joinBuilder strings.Builder
	var conditions []string
	var params []interface{}

	for i, key := range attributeKeys {
		ua := fmt.Sprintf("ua%d", i)
		a := fmt.Sprintf("a%d", i)

		joinBuilder.WriteString(fmt.Sprintf(`
left join user_attribute %s on %s.user_id = u.id
left join attribute %s on %s.id = %s.attribute_id
`, ua, ua, a, a, ua))

		var sb strings.Builder
		sb.WriteString("(")
		sb.WriteString(fmt.Sprintf("%s.key = $%d and (", a, *paramIndex))
		params = append(params, key)
		*paramIndex++

		for j, val := range values {
			if j > 0 {
				sb.WriteString(" or ")
			}
			sb.WriteString(fmt.Sprintf("unaccent(%s.value) ilike $%d", ua, *paramIndex))
			params = append(params, "%"+val+"%")
			*paramIndex++
		}

		sb.WriteString("))")
		conditions = append(conditions, sb.String())
	}

	return joinBuilder.String(), strings.Join(conditions, " or "), params
}

func (u *userRepositoryImpl) safeOrder(sort string) string {
	allowed := map[string]string{
		"id":         "u.id",
		"created_at": "u.created_at",
		"email":      "u.email",
		"confirmed":  "u.confirmed",
		"enabled":    "u.enabled",
	}
	defaultOrder := "u.email asc"

	if strings.TrimSpace(sort) == "" {
		return defaultOrder
	}

	parts := common.SplitWithoutBlank(sort, " ")
	out := make([]string, 0, len(parts))
	for _, raw := range parts {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		// split on whitespace between field and dir
		toks := strings.Fields(s)
		field := strings.ToLower(toks[0])
		col, ok := allowed[field]
		if !ok {
			continue
		}
		dir := "asc"
		if len(toks) > 1 {
			d := strings.ToLower(toks[1])
			if d == "asc" || d == "desc" {
				dir = d
			}
		}
		out = append(out, fmt.Sprintf("%s %s", col, dir))
	}
	if len(out) == 0 {
		return defaultOrder
	}
	return strings.Join(out, " ")
}
