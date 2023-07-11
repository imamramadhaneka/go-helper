package standard

import "math"

// Result common output
type Result struct {
	Data  interface{}
	Error error
}

// SliceResult include meta
type SliceResult struct {
	Data  interface{}
	Meta  Meta
	Error error
}

// Meta model
type Meta struct {
	Pagination *Pagination `json:"pagination,omitempty"`
	Filter     *MetaFilter `json:"filter,omitempty"`
	Message    string      `json:"message"`
}

// Pagination model
type Pagination struct {
	Page    int `json:"page"`
	PerPage int `json:"perPage"`
	MaxPage int `json:"maxPage"`
	Total   int `json:"total"`
}

// Filter model
type MetaFilter struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Data MetaFilterData
}

// Data model
type MetaFilterData struct {
	ID   int    `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// NewMeta create new meta for slice data
func NewMeta(page, limit, totalRecords int) (m Meta) {
	paging := &Pagination{
		Page:    page,
		PerPage: limit,
		MaxPage: int(math.Ceil(float64(totalRecords) / float64(limit))),
		Total:   totalRecords,
	}
	m.Pagination = paging
	return m
}
