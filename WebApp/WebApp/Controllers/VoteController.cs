using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApp.Data;
using WebApp.Models;

namespace WebApp.Controllers
{
    public class VoteController : Controller
    {
        private readonly WebAppContext _context;

        public VoteController(WebAppContext context)
        {
            _context = context;
        }
        public IActionResult Index()
        {
            List<Vote> votes = new List<Vote>();
            votes = _context.Vote.ToList();
            return View(votes);
        }
        public IActionResult Voting(Int64 id)
        {
            ViewData["VoteId"] = id;
            List<Answer> answers = _context.Answer.Where(s => s.VoteId == id).ToList();
            return View(answers);
        }
    }
}
