package tool

type Info struct {
    dburl string
}

func (u Info) GetDBUrl() string {
     // elephantSQL の Detail に表示されている URL を記述
    return "postgres://bqjzyboe:jGKs-NMuWT2JIvL59Dai1CRleuKBplAP@satao.db.elephantsql.com:5432/bqjzyboe"
}