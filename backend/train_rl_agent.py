"""
Script to train RL agent for cybersecurity threat response
Run this to train a PPO agent on the CyberSecurityEnv
"""
import os
import sys
from pathlib import Path

# Add app to path
backend_path = Path(__file__).parent
sys.path.insert(0, str(backend_path))

from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import EvalCallback
from app.services.rl_env import CyberSecurityEnv


def train_agent(total_timesteps: int = 100000):
    """Train PPO agent on cybersecurity environment"""
    print("🚀 Starting RL agent training...")
    
    # Create environment
    env = CyberSecurityEnv()
    
    # Create evaluation environment
    eval_env = CyberSecurityEnv()
    
    # Create model directory
    model_dir = Path("models")
    model_dir.mkdir(exist_ok=True)
    
    # Initialize PPO agent
    model = PPO(
        "MlpPolicy",
        env,
        verbose=1,
        learning_rate=3e-4,
        n_steps=2048,
        batch_size=64,
        n_epochs=10,
        gamma=0.99,
        gae_lambda=0.95,
        clip_range=0.2,
        ent_coef=0.01,
        tensorboard_log="./tensorboard_logs/"
    )
    
    # Evaluation callback
    eval_callback = EvalCallback(
        eval_env,
        best_model_save_path=str(model_dir / "best"),
        log_path=str(model_dir / "logs"),
        eval_freq=5000,
        deterministic=True,
        render=False
    )
    
    # Train agent
    print(f"Training for {total_timesteps} timesteps...")
    model.learn(
        total_timesteps=total_timesteps,
        callback=eval_callback,
        progress_bar=True
    )
    
    # Save final model
    model_path = model_dir / "rl_agent.zip"
    model.save(str(model_path))
    print(f"✅ Model saved to {model_path}")
    
    # Test agent
    print("\n🧪 Testing trained agent...")
    obs, _ = env.reset()
    for _ in range(10):
        action, _ = model.predict(obs, deterministic=True)
        obs, reward, terminated, truncated, info = env.step(action)
        print(f"Action: {info['action']}, Threat: {info['threat_type']}, Reward: {reward:.2f}")
        if terminated or truncated:
            obs, _ = env.reset()
    
    print("✅ Training complete!")


if __name__ == "__main__":
    timesteps = int(os.getenv("RL_TRAINING_TIMESTEPS", "100000"))
    train_agent(timesteps)
