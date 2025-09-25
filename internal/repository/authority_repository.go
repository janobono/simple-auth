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

type AuthorityRepository interface {
	AddAuthority(ctx context.Context, data *AuthorityData) (*Authority, error)
	CountById(ctx context.Context, id pgtype.UUID) (int64, error)
	CountByAuthority(ctx context.Context, authority string) (int64, error)
	CountByAuthorityAndNotId(ctx context.Context, authority string, id pgtype.UUID) (int64, error)
	DeleteAll(ctx context.Context) error
	DeleteAuthorityById(ctx context.Context, id pgtype.UUID) error
	GetAllAuthorities(ctx context.Context) ([]*Authority, error)
	GetAuthorityById(ctx context.Context, id pgtype.UUID) (*Authority, error)
	GetAuthorityByAuthority(ctx context.Context, authority string) (*Authority, error)
	SearchAuthorities(ctx context.Context, criteria *SearchAuthoritiesCriteria, pageable *common.Pageable) (*common.Page[*Authority], error)
	SetAuthority(ctx context.Context, id pgtype.UUID, data *AuthorityData) (*Authority, error)
}

type authorityRepositoryImpl struct {
	dataSource *db.DataSource
}

func NewAuthorityRepository(dataSource *db.DataSource) AuthorityRepository {
	return &authorityRepositoryImpl{dataSource}
}

func (a *authorityRepositoryImpl) AddAuthority(ctx context.Context, data *AuthorityData) (*Authority, error) {
	authority, err := a.dataSource.Queries.AddAuthority(ctx, sqlc.AddAuthorityParams{
		ID:        db2.NewUUID(),
		Authority: data.Authority,
	})
	if err != nil {
		return nil, err
	}
	return toAuthority(&authority), nil
}

func (a *authorityRepositoryImpl) CountById(ctx context.Context, id pgtype.UUID) (int64, error) {
	return a.dataSource.Queries.CountAuthoritiesById(ctx, id)
}

func (a *authorityRepositoryImpl) CountByAuthority(ctx context.Context, authority string) (int64, error) {
	return a.dataSource.Queries.CountAuthoritiesByAuthority(ctx, authority)
}

func (a *authorityRepositoryImpl) CountByAuthorityAndNotId(ctx context.Context, authority string, id pgtype.UUID) (int64, error) {
	return a.dataSource.Queries.CountAuthoritiesByAuthorityNotId(ctx, sqlc.CountAuthoritiesByAuthorityNotIdParams{
		Authority: authority,
		ID:        id,
	})
}

func (a *authorityRepositoryImpl) DeleteAll(ctx context.Context) error {
	return a.dataSource.Queries.TruncateTableAuthority(ctx)
}

func (a *authorityRepositoryImpl) DeleteAuthorityById(ctx context.Context, id pgtype.UUID) error {
	return a.dataSource.Queries.DeleteAuthorityById(ctx, id)
}

func (a *authorityRepositoryImpl) GetAllAuthorities(ctx context.Context) ([]*Authority, error) {
	authorities, err := a.dataSource.Queries.GetAllAuthorities(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*Authority, len(authorities))
	for index, authority := range authorities {
		result[index] = toAuthority(&authority)
	}
	return result, nil
}

func (a *authorityRepositoryImpl) GetAuthorityById(ctx context.Context, id pgtype.UUID) (*Authority, error) {
	dbAuthority, err := a.dataSource.Queries.GetAuthorityById(ctx, id)
	if err != nil {
		return nil, err
	}
	return toAuthority(&dbAuthority), nil
}

func (a *authorityRepositoryImpl) GetAuthorityByAuthority(ctx context.Context, authority string) (*Authority, error) {
	dbAuthority, err := a.dataSource.Queries.GetAuthorityByAuthority(ctx, authority)
	if err != nil {
		return nil, err
	}
	return toAuthority(&dbAuthority), nil
}

func (a *authorityRepositoryImpl) SearchAuthorities(ctx context.Context, criteria *SearchAuthoritiesCriteria, pageable *common.Pageable) (*common.Page[*Authority], error) {
	if criteria == nil {
		return nil, ErrNilCriteria
	}
	if pageable == nil {
		return nil, ErrNilPageable
	}

	totalRows, err := a.countAuthorities(ctx, criteria)
	if err != nil {
		return nil, err
	}

	content, err := a.searchAuthorities(ctx, criteria, pageable)
	if err != nil {
		return nil, err
	}

	return common.NewPage[*Authority](pageable, totalRows, content), nil
}

func (a *authorityRepositoryImpl) SetAuthority(ctx context.Context, id pgtype.UUID, data *AuthorityData) (*Authority, error) {
	authority, err := a.dataSource.Queries.SetAuthority(ctx, sqlc.SetAuthorityParams{
		ID:        id,
		Authority: data.Authority,
	})
	if err != nil {
		return nil, err
	}
	return toAuthority(&authority), nil
}

func (a *authorityRepositoryImpl) countAuthorities(ctx context.Context, criteria *SearchAuthoritiesCriteria) (int64, error) {
	if criteria == nil {
		return 0, ErrNilCriteria
	}

	var query strings.Builder
	query.WriteString("select count(*) from authority")

	paramIndex := 1
	conditions, parameters := a.buildSearchQueryParts(criteria, &paramIndex)

	if len(conditions) > 0 {
		query.WriteString(" where ")
		query.WriteString(strings.Join(conditions, " and "))
	}

	row := a.dataSource.Pool.QueryRow(ctx, query.String(), parameters...)
	var count int64
	err := row.Scan(&count)
	return count, err
}

func (a *authorityRepositoryImpl) searchAuthorities(ctx context.Context, criteria *SearchAuthoritiesCriteria, pageable *common.Pageable) ([]*Authority, error) {
	if criteria == nil {
		return nil, ErrNilCriteria
	}
	if pageable == nil {
		return nil, ErrNilPageable
	}

	var query strings.Builder
	query.WriteString("select id, authority from authority")

	paramIndex := 1
	conditions, parameters := a.buildSearchQueryParts(criteria, &paramIndex)

	if len(conditions) > 0 {
		query.WriteString(" where ")
		query.WriteString(strings.Join(conditions, " and "))
	}

	query.WriteString(" order by " + pageable.Sort)
	query.WriteString(fmt.Sprintf(" limit %d offset %d", pageable.Limit(), pageable.Offset()))

	rows, err := a.dataSource.Pool.Query(ctx, query.String(), parameters...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var content []*Authority
	for rows.Next() {
		var authority sqlc.Authority
		if err := rows.Scan(
			&authority.ID,
			&authority.Authority,
		); err != nil {
			return nil, err
		}
		content = append(content, toAuthority(&authority))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return content, nil
}

func (a *authorityRepositoryImpl) buildSearchQueryParts(criteria *SearchAuthoritiesCriteria, paramIndex *int) (conditions []string, parameters []interface{}) {
	conditions = []string{}
	parameters = []interface{}{}

	if cond, params := a.buildSearchFieldConditions(criteria.SearchField, paramIndex); cond != "" {
		conditions = append(conditions, cond)
		parameters = append(parameters, params...)
	}

	return conditions, parameters
}

func (a *authorityRepositoryImpl) buildSearchFieldConditions(searchField string, paramIndex *int) (string, []interface{}) {
	values := common.SplitWithoutBlank(searchField, " ")
	if len(values) == 0 {
		return "", nil
	}

	var sb strings.Builder
	params := make([]interface{}, 0, len(values))

	sb.WriteString("(")
	for i, val := range values {
		if i > 0 {
			sb.WriteString(" or ")
		}
		sb.WriteString(fmt.Sprintf("authority like $%d", *paramIndex))
		params = append(params, "%"+val+"%")
		*paramIndex++
	}
	sb.WriteString(")")
	return sb.String(), params
}
