event http_reply(c: connection, version: string, code: count, reason: string) 
{
    SumStats::observe("all res",  SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    if (code == 404) 
{
        SumStats::observe("404 res", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
        SumStats::observe("uni 404 res", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
}


event zeek_init()
{
    local s1 = SumStats::Reducer($stream="all res",  $apply=set(SumStats::SUM));
    local s2 = SumStats::Reducer($stream="404 res", $apply=set(SumStats::SUM));
    local s3 = SumStats::Reducer($stream="uni 404 res", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name = "detect attacker through 404 resp",$epoch = 10min,$reducers = set(s1,s2,s3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                            local rate1 : double = result["404 res"]$sum / result["all res"]$sum;
                            local rate2 : double = result["uni 404 res"]$unique / result["404 res"]$sum;
                            if (result["404 res"]$sum > 2 && rate1 > 0.2 && rate2 > 0.5) 
	            {
                                print fmt("%s scan the  %.0f urls with %.0f scan actions ", key$host, result["404 res"]$sum, result["uni 404 res"]$sum);
                            }
                        }]);
    }


