import { useState } from 'react'
import './App.css'
import MyInput from './components/input.jsx'


function App() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [rememberMe, setRememberMe] = useState(false)

  const handleEmailChange = (e) => {
    setEmail(e.target.value)
  }

  const handlePasswordChange = (e) => {
    setPassword(e.target.value)
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    console.log("Form submitted:", { email, password, rememberMe })
    alert("Login successful!")
  }

  return (
    <>
    <div className='bg'>
      <div className="right">
          <div className="form-container">
            <h1 className='title'>HELLO</h1>
            <p className="subtitle">Sign in to your account</p>
            <form onSubmit={handleSubmit}>
              <MyInput 
                label="Email" 
                type="email" 
                placeholder="Enter your email"
                value={email}
                onChange={handleEmailChange}
              />
              <MyInput 
                label="Password" 
                type="password" 
                placeholder="Enter your password"
                value={password}
                onChange={handlePasswordChange}
              />
              <div className='type'>
                <div className="checkbox-wrapper">
                  <input 
                    type="checkbox" 
                    id="rememberMe" 
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                  />
                  <label htmlFor="rememberMe"> Remember Me</label> 
                </div>
                <a href="#" className="forgot-link">Forgot Password?</a>
              </div>
              <button type="submit" className='btn' onClick={handleSubmit}>Submit</button>
            </form>
          </div>
        </div>
        <div className="left">
        <div className="info">
        <h1>Hello There</h1>
        <h1>Welcome Back!</h1>
        <p>To keep connected with us please login with your personal info</p>
        </div>
      </div>
    </div>
    </>
  )
}


export default App