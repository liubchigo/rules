namespace lib.Response
{
    public class ServiceEndpointHistory
    {
        public ServiceEndpointHistoryData Data { get; set; }


    }

    public class ServiceEndpointHistoryData
    {
        public ReleaseDefinition Definition { get; set; }
    }
}