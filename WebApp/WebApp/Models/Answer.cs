using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebApp.Models
{
    public class Answer
    {
        public Int64 AnswerId { get; set; }
        public string Content { get; set; }
        public Int64 Count { get; set; }
        public Int64 VoteId { get; set; }
    }
}
