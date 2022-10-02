using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController :BaseApiController
    {
        private readonly ITokenService _tokenservice;

        private DataContext _context { get; }

        public AccountController(DataContext context , ITokenService tokenservice)
        {
            _context = context;
            _tokenservice = tokenservice;
        }
        
        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto Register){

            if(await UserExists(Register.Username )) return BadRequest("Username is taken");

            using var hmac = new HMACSHA512();
            var user = new AppUser{
                UserName = Register.Username.ToLower() ,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(Register.Password)) ,
                PasswordSalt = hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto{
                Username = user.UserName,
                Token = _tokenservice.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto){

            var user = await _context.Users.SingleOrDefaultAsync(
                x => x.UserName == loginDto.Username
            );

            if (user == null) return Unauthorized("username invalid");

            using var hmac = new HMACSHA512();
            var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password)); 
            
            for(int i = 0 ; i <= computeHash.Length ; i++){
                if (computeHash[i] != user.PasswordHash[i]) return Unauthorized("Password invalid");
            }
            return new UserDto{
                Username = user.UserName,
                Token = _tokenservice.CreateToken(user)
            };
        }
        private async Task<bool> UserExists(string Username){
            return await _context.Users.AnyAsync( x => x.UserName == Username.ToLower() );
        }
    }
}