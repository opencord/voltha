package common

import (
	"github.com/opencord/voltha/protos/go/openflow_13"
)

type SortByPriority []*openflow_13.OfpFlowStats

func (s SortByPriority) Len() int {
	return len(s)
}
func (s SortByPriority) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s SortByPriority) Less(i, j int) bool {
	return s[i].Priority < s[j].Priority
}
