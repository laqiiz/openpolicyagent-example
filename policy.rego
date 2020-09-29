package test

deny_tags_multiple[msg] {
	some path, method
    count(input.paths[path][method].tags) != 1               # タグが複数設定
    msg := sprintf("path(%v) method(%v) tags must keep only one", [path, method])
}

deny_tags_none[msg] {
	some path, method
    object.get(input.paths[path][method], "tags", "none") == "none" # タグが存在しない場合
    msg := sprintf("path(%v) method(%v) tags must keep only one", [path, method])
}

deny_opeId_snake_case[msg] {
	some path, method
    opeId := input.paths[path][method].operationId

    count(split(opeId, "_")) != 1                           # snake_caseじゃないこと
    msg := sprintf("path(%v) method(%v) operationId must be camelCase: %v", [path, method, opeId])
}

deny_opeId_not_camel_case[msg] {
	some path, method
    opeId := input.paths[path][method].operationId

    substring(opeId, 0, 1) != lower(substring(opeId, 0, 1)) # 最初の1文字が小文字
    msg := sprintf("path(%v) method(%v) operationId must be camelCase: %v", [path, method, opeId])
}

deny_opeId_startwith_http_method[msg] {
	some path, method
    opeId := input.paths[path][method].operationId

    indexof(opeId, method) != 0  # HTTPメソッドから始まっていない
    msg := sprintf("path(%v) method(%v) operationId must be startwith http method: %v", [path, method, opeId])
}
