-- Keep a newly accepted registration connection open while its elected Router
-- boots. Accepting then immediately closing it causes the released Java reader
-- and writer to race their reconnect handlers. No application bytes are sent to
-- an alternate Router: the installed selector still owns the backend choice.
core.register_action("wait-for-router", { "tcp-req" }, function(txn, backend)
    -- Bound reconnect attempts during the brief health-check detection window.
    core.msleep(250)
    while txn.f:nbsrv(backend) == 0 do
        core.msleep(100)
    end
end, 1)
