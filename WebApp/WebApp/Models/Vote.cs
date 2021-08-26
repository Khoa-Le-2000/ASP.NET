using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebApp.Models
{
    public class Vote
    {
        public Int64 VoteId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
    }
}
