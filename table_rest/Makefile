
all:
	go build

test: test_sql_1 test_param_1

test_sql_1:
	go test -v -run CrudSql

test_param_1:
	go test -v -run ParamParsingAndRetreval

test_route_1:
	go test -v -run RouteCRUD

