"""

This script processes a JSON file containing data, computes weekly statistics, generates zero-knowledge proofs (ZKPs) using the noknow library, 
and stores the results in a blockchain. It also verifies the integrity of the blockchain and logs all operations.
The script includes functions for hashing data, generating ZKPs, and creating a blockchain. 
It uses the pandas library to manipulate data and the hashlib library for hashing. 
The blockchain is stored in JSON files with timestamps to avoid overwriting previous versions. 
The script also includes error handling and logging for debugging purposes.   

2025-04-24 Volker.Engels|Thomas.Hanke(at fom.de) et al. Version 0.0.15

https://github.com/FOM-mile-Institut/pallet_price_index_zero_trust_blockchain

"""
import pandas as pd
import json
import hashlib
import time
from datetime import datetime
import os
import logging
import glob
import re
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof

# Set up logging
logging.basicConfig(filename='blockchain.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Blockchain class
class Blockchain:
    def __init__(self, difficulty=4):
        self.chain = []
        self.difficulty = difficulty
        self.load_chain()
        if not self.chain:
            genesis_block = self.create_block(previous_hash='0', stats=None, data_hash='', proof='', signature='')
            logging.info("Created genesis block")
            self.chain = [genesis_block]

    def create_block(self, previous_hash, stats, data_hash, proof, signature):
        data_hash = str(data_hash) if data_hash is not None else ''
        # Validate ZKP objects
        proof_str = ''
        signature_str = ''
        if stats is not None:  # Non-genesis block
            if not isinstance(proof, ZKProof):
                logging.error(f"Invalid proof for block #{len(self.chain)}: {proof} (type: {type(proof)})")
                raise ValueError("Proof must be a ZKProof object")
            if not isinstance(signature, ZKSignature):
                logging.error(f"Invalid signature for block #{len(self.chain)}: {signature} (type: {type(signature)})")
                raise ValueError("Signature must be a ZKSignature object")
            proof_str = proof.dump()
            signature_str = signature.dump()
            logging.debug(f"Block #{len(self.chain)} proof: {proof_str}")
            logging.debug(f"Block #{len(self.chain)} signature: {signature_str}")
        block = {
            'index': len(self.chain),
            'timestamp': int(time.time()),
            'stats': stats,
            'data_hash': data_hash,
            'proof': proof_str,
            'signature': signature_str,
            'previous_hash': previous_hash,
            'nonce': 0,
            'hash': ''
        }
        block = self.proof_of_work(block)
        self.chain.append(block)
        self.save_chain()
        self.log_audit(f"Block #{block['index']} created: Data Hash={data_hash}, Stats={stats}")
        logging.info(f"Created block #{block['index']} for stats: {stats}")
        return block

    def proof_of_work(self, block):
        block['nonce'] = 0
        computed_hash = self.compute_block_hash(block)
        while not computed_hash.startswith('0' * self.difficulty):
            block['nonce'] += 1
            computed_hash = self.compute_block_hash(block)
        block['hash'] = computed_hash
        return block

    def compute_block_hash(self, block):
        block_string = json.dumps(
            {k: v for k, v in block.items() if k != 'hash'},
            sort_keys=True
        ).encode()
        return hashlib.sha256(block_string).hexdigest()

    def verify_chain(self):
        for i in range(len(self.chain)):
            current = self.chain[i]
            computed_hash = self.compute_block_hash(current)
            if current['hash'] != computed_hash:
                logging.error(f"Block #{i} hash mismatch: stored={current['hash']}, computed={computed_hash}")
                return False
            if not current['hash'].startswith('0' * self.difficulty):
                logging.error(f"Block #{i} fails PoW: hash={current['hash']}")
                return False
            if i > 0:
                previous = self.chain[i - 1]
                if current['previous_hash'] != previous['hash']:
                    logging.error(f"Block #{i} previous_hash mismatch: stored={current['previous_hash']}, expected={previous['hash']}")
                    return False
                if current['stats'] is None:
                    logging.error(f"Block #{i} has no stats")
                    return False
                if not self.verify_zkp(current):
                    logging.error(f"Block #{i} ZKP verification failed")
                    return False
            logging.debug(f"Block #{i} passed verification")
        return True

    def verify_zkp(self, block):
        if block['index'] == 0:  # Genesis block has no ZKP
            return True
        try:
            signature_str = block['signature']
            proof_str = block['proof']
            logging.debug(f"Verifying block #{block['index']} signature: {signature_str}")
            logging.debug(f"Verifying block #{block['index']} proof: {proof_str}")
            if not signature_str or not proof_str:
                logging.error(f"Block #{block['index']} missing signature or proof: signature={signature_str}, proof={proof_str}")
                return False
            signature = ZKSignature.load(signature_str)
            proof = ZKProof.load(proof_str)
            zk = ZK(signature.params)
            token = block['data_hash']
            # Construct ZKData
            data = ZKData(data=token, proof=proof)
            logging.debug(f"Block #{block['index']} ZKData: {data}")
            # Use the same ZKData for verification
            result = zk.verify(data, signature, data=data)
            logging.debug(f"Block #{block['index']} ZKP verification: {result}")
            return result
        except Exception as e:
            logging.error(f"ZKP verification failed for block #{block['index']}: {str(e)}")
            return False

    def get_latest_block(self):
        return self.chain[-1]

    def save_chain(self):
        # Generate filename with current datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'blockchain_{timestamp}.json'
        with open(filename, 'w') as f:
            json.dump(self.chain, f, indent=2)
        logging.info(f"Saved blockchain to {filename}")

    def load_chain(self):
        # Look for datetime-based blockchain files
        blockchain_files = glob.glob('blockchain_*.json')
        if blockchain_files:
            # Extract timestamps from filenames and sort by datetime
            def get_timestamp(file):
                match = re.search(r'blockchain_(\d{8}_\d{6})\.json', file)
                if match:
                    try:
                        return datetime.strptime(match.group(1), '%Y%m%d_%H%M%S')
                    except ValueError:
                        return datetime.min
                return datetime.min

            # Load the most recent file
            latest_file = max(blockchain_files, key=get_timestamp)
            try:
                with open(latest_file, 'r') as f:
                    loaded_chain = json.load(f)
                logging.info(f"Loaded blockchain from {latest_file}")
                for block in loaded_chain:
                    required_keys = ['index', 'timestamp', 'previous_hash', 'nonce', 'hash']
                    if not all(key in block for key in required_keys):
                        logging.error(f"Invalid block structure in {latest_file}: {block}")
                        return
                    block.setdefault('data_hash', '')
                    block.setdefault('proof', '')
                    block.setdefault('stats', None)
                    block.setdefault('signature', '')
                    if block['index'] > 0 and (not block['signature'] or not block['proof']):
                        logging.error(f"Non-genesis block #{block['index']} missing signature or proof in {latest_file}")
                        return
                    if block['hash'] != self.compute_block_hash(block):
                        logging.error(f"Block #{block['index']} hash mismatch in {latest_file}")
                        return
                self.chain = loaded_chain
                if not self.verify_chain():
                    logging.error(f"Loaded chain from {latest_file} is invalid, starting new chain")
                    self.chain = []
            except (json.JSONDecodeError, ValueError):
                logging.error(f"Corrupted {latest_file}, starting new chain")
                self.chain = []
        else:
            # Fallback to legacy blockchain.json
            if os.path.exists('blockchain.json'):
                try:
                    with open('blockchain.json', 'r') as f:
                        loaded_chain = json.load(f)
                    logging.info("Loaded blockchain from blockchain.json")
                    for block in loaded_chain:
                        required_keys = ['index', 'timestamp', 'previous_hash', 'nonce', 'hash']
                        if not all(key in block for key in required_keys):
                            logging.error(f"Invalid block structure in blockchain.json: {block}")
                            return
                        block.setdefault('data_hash', '')
                        block.setdefault('proof', '')
                        block.setdefault('stats', None)
                        block.setdefault('signature', '')
                        if block['index'] > 0 and (not block['signature'] or not block['proof']):
                            logging.error(f"Non-genesis block #{block['index']} missing signature or proof")
                            return
                        if block['hash'] != self.compute_block_hash(block):
                            logging.error(f"Block #{block['index']} hash mismatch in loaded chain")
                            return
                    self.chain = loaded_chain
                    if not self.verify_chain():
                        logging.error("Loaded chain from blockchain.json is invalid, starting new chain")
                        self.chain = []
                except (json.JSONDecodeError, ValueError):
                    logging.error("Corrupted blockchain.json, starting new chain")
                    self.chain = []

    def log_audit(self, message):
        with open('audit_log.txt', 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] {message}\n")

    def has_week(self, year_week):
        for block in self.chain:
            if block['stats'] and block['stats'].get('year_week') == year_week:
                return True
        return False

# Real ZKP function using noknow
def generate_zkp(amounts, prices, dates, total_amount, datapoint_count, avg_price_per_day, median_price, weighted_avg_price):
    try:
        # Verify stats
        computed_sum = sum(amounts)
        computed_count = len(amounts)
        daily_prices = {}
        for price, date in zip(prices, dates):
            date_str = str(date)
            if date_str not in daily_prices:
                daily_prices[date_str] = []
            daily_prices[date_str].append(price)
        daily_averages = [sum(prices) / len(prices) for prices in daily_prices.values()]
        computed_avg = sum(daily_averages) / len(daily_averages) if daily_averages else 0
        # Compute median price to match pandas behavior
        sorted_prices = sorted(prices)
        n = len(sorted_prices)
        if n == 0:
            computed_median = 0
        elif n % 2 == 0:
            computed_median = (sorted_prices[n // 2 - 1] + sorted_prices[n // 2]) / 2
        else:
            computed_median = sorted_prices[n // 2]
        # Compute weighted average price
        total_weighted_price = sum(p * a for p, a in zip(prices, amounts))
        total_amount_sum = sum(amounts)
        computed_weighted_avg = total_weighted_price / total_amount_sum if total_amount_sum > 0 else 0
        is_valid = (
            computed_sum == total_amount and
            computed_count == datapoint_count and
            abs(computed_avg - avg_price_per_day) < 0.0001 and
            abs(computed_median - median_price) < 0.0001 and
            abs(computed_weighted_avg - weighted_avg_price) < 0.0001
        )
        if not is_valid:
            logging.error(f"ZKP verification failed: computed_sum={computed_sum}, total_amount={total_amount}, "
                          f"computed_count={computed_count}, datapoint_count={datapoint_count}, "
                          f"computed_avg={computed_avg}, avg_price_per_day={avg_price_per_day}, "
                          f"computed_median={computed_median}, median_price={median_price}, "
                          f"computed_weighted_avg={computed_weighted_avg}, weighted_avg_price={weighted_avg_price}")
            return None, None

        # Create secret from stats
        secret = f"{total_amount}_{datapoint_count}_{avg_price_per_day}_{median_price}_{weighted_avg_price}"
        zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")
        signature = zk.create_signature(secret)
        logging.debug(f"Generated ZKP signature for secret: {secret}")
        return signature, secret
    except Exception as e:
        logging.error(f"ZKP generation failed: {str(e)}")
        return None, None

# Function to hash input data
def hash_data(data):
    serializable_data = [
        {
            'amount': record['amount'],
            'price': record['price'],
            'date': str(record['date'])
        }
        for record in data
    ]
    return hashlib.sha256(json.dumps(serializable_data, sort_keys=True).encode()).hexdigest()

# Read JSON file anonymized_data_specific
try:
    with open('anonymized_data_specific.json', 'r') as file:
        data = json.load(file)
except FileNotFoundError:
    print("Error: anonymized_data_specific.json not found")
    exit(1)

# Extract nested data and create DataFrame
try:
    nested_data = data['data'][0]
    df = pd.DataFrame(nested_data)
except (KeyError, IndexError):
    print("Error: Invalid JSON structure")
    exit(1)

# Convert date to datetime
df['date'] = pd.to_datetime(df['date'])

# Extract year-week for grouping (Sunday-start weeks)
df['year_week'] = df['date'].dt.strftime('%Y-W%U')

# Compute weekly stats
weekly_stats = df.groupby('year_week').agg(
    total_amount=('amount', 'sum'),
    datapoint_count=('amount', 'count'),
    median_price=('price', 'median'),
).reset_index()

# Compute average price per day
daily_avg_price = df.groupby(['year_week', df['date'].dt.date])['price'].mean().reset_index()
weekly_avg_price = daily_avg_price.groupby('year_week')['price'].mean().reset_index(name='avg_price_per_day')

# Compute weighted average price: Σ(price * amount) / Σ(amount)
df['weighted_price'] = df['price'] * df['amount']
weekly_weighted_price = df.groupby('year_week').agg(
    total_weighted_price=('weighted_price', 'sum'),
    total_amount=('amount', 'sum')
).reset_index()
weekly_weighted_price['weighted_avg_price'] = weekly_weighted_price['total_weighted_price'] / weekly_weighted_price['total_amount']

# Merge stats
weekly_stats = weekly_stats.merge(weekly_avg_price, on='year_week')
weekly_stats = weekly_stats.merge(
    weekly_weighted_price[['year_week', 'weighted_avg_price']],
    on='year_week'
)

# Initialize blockchain
blockchain = Blockchain(difficulty=4)

# Process each week and add to blockchain
for _, row in weekly_stats.iterrows():
    year_week = row['year_week']
    if blockchain.has_week(year_week):
        print(f"Skipping {year_week}: already in blockchain")
        logging.info(f"Skipped {year_week}: already in blockchain")
        continue
    total_amount = int(row['total_amount'])
    datapoint_count = int(row['datapoint_count'])
    avg_price_per_day = float(row['avg_price_per_day'])
    median_price = float(row['median_price'])
    weighted_avg_price = float(row['weighted_avg_price'])

    # Filter data for this week
    week_data = [
        {
            'amount': record['amount'],
            'price': record['price'],
            'date': str(record['date'])
        }
        for _, record in df[df['year_week'] == year_week][['amount', 'price', 'date']].iterrows()
    ]
    data_hash = hash_data(week_data)

    # Generate ZKP
    amounts = [x['amount'] for x in week_data]
    prices = [x['price'] for x in week_data]
    dates = [x['date'] for x in week_data]
    signature, secret = generate_zkp(
        amounts, prices, dates, total_amount, datapoint_count, avg_price_per_day, median_price, weighted_avg_price
    )
    
    if not signature or not secret:
        print(f"Failed to generate ZKP for {year_week}")
        logging.error(f"Failed to generate ZKP for {year_week}")
        continue

    # Generate proof using data_hash as token
    try:
        zk = ZK(signature.params)
        proof_data = zk.sign(secret, data_hash)
        proof = proof_data.proof
        if not isinstance(proof, ZKProof):
            logging.error(f"Invalid ZKP proof for {year_week}: {proof} (type: {type(proof)})")
            print(f"Failed to generate valid ZKP proof for {year_week}")
            continue
        logging.debug(f"Generated ZKP proof for {year_week} with data_hash: {data_hash}")
    except Exception as e:
        logging.error(f"Failed to generate ZKP proof for {year_week}: {str(e)}")
        print(f"Failed to generate ZKP proof for {year_week}")
        continue

    # Create stats dictionary
    stats = {
        'year_week': year_week,
        'total_amount': total_amount,
        'datapoint_count': datapoint_count,
        'avg_price_per_day': avg_price_per_day,
        'median_price': median_price,
        'weighted_avg_price': weighted_avg_price
    }

    # Add block to blockchain
    previous_block = blockchain.get_latest_block()
    blockchain.create_block(
        previous_hash=previous_block['hash'],
        stats=stats,
        data_hash=data_hash,
        proof=proof,
        signature=signature
    )
    print(f"Block created for {year_week}")

# Verify blockchain integrity
is_valid = blockchain.verify_chain()
print("\nBlockchain Integrity:", "Valid" if is_valid else "Invalid")
if not is_valid:
    logging.warning("Blockchain verification failed")

# Display blockchain
print("\nBlockchain Contents:")
for block in blockchain.chain:
    print(f"Block #{block['index']}:")
    print(f"  Timestamp: {datetime.fromtimestamp(block['timestamp'])}")
    print(f"  Stats: {block.get('stats', 'None')}")
    print(f"  Data Hash: {block.get('data_hash', '')[:16]}...")
    print(f"  Proof: {block.get('proof', '')[:16]}...")
    print(f"  Signature: {block.get('signature', '')[:16]}...")
    print(f"  Previous Hash: {block.get('previous_hash', '')[:16]}...")
    print(f"  Hash: {block.get('hash', '')[:16]}...\n")