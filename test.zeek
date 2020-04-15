@load base/frameworks/sumstats
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="404_founder", $apply=set(SumStats::UNIQUE));
    local r2 = SumStats::Reducer($stream="all_founder", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="scan_founder",
                      $epoch=10mins,
                      $reducers=set(r1,r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local result1 = result["404_founder"];
                        local result2 = result["all_founder"];
                        if(result1$num>2 && (result1$num*100/result2$num)>20 &&
                                     (result1$unique*100/result1$num)>50)
                        	{
                        	 print fmt("%s is a scanner with %d scan attempts on %d urls", 
                        	 key$host, result2$num,result2$unique);
                        	}
                        }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    SumStats::observe("all_founder", [$host=c$id$orig_h], [$str=c$http$uri]);
    if(code == 404)
    	{
    	SumStats::observe("404_founder", [$host=c$id$orig_h], [$str=c$http$uri]);
    	}
    }
