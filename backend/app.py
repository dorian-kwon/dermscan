import base64
import json
import logging
import os
import re
import sqlite3
import uuid

import requests
from flask import Flask, request, jsonify, render_template, url_for, redirect, session
from werkzeug.utils import secure_filename

from backend.models.swin_model import SwinModel
from models.vi_model import ViModel
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)



app = Flask(__name__)

# SQLite 데이터베이스 설정
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dermscan.db')

# 데이터베이스 초기화 함수
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # 피드백 테이블 초기화
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='feedback'")
    feedback_table_exists = cursor.fetchone() is not None
    
    if not feedback_table_exists:
        # 피드백 테이블 생성 (없는 경우)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image_path TEXT NOT NULL,
            model TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            score INTEGER NOT NULL,
            diagnoses TEXT,  /* JSON 형식으로 저장 */
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        logger.info("피드백 테이블이 생성되었습니다.")
    
    # 분석 로그 테이블 초기화
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analysis_log'")
    log_table_exists = cursor.fetchone() is not None
    
    if not log_table_exists:
        # 분석 로그 테이블 생성 (없는 경우)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image_path TEXT NOT NULL,
            model TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            diagnoses TEXT,  /* JSON 형식으로 저장 */
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        logger.info("분석 로그 테이블이 생성되었습니다.")
    
    conn.commit()
    conn.close()
    logger.info("SQLite 데이터베이스가 초기화되었습니다.")

# 데이터베이스 초기화 실행
init_db()

# 시크릿 키 설정
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dermscan-secret-key')

# OpenAI API 설정 - 빈 값으로 초기화하고 API를 통해 설정 가능하게 함
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
app.config['OPENAI_API_KEY'] = OPENAI_API_KEY

# 업로드 폴더 설정
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB 제한
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# 허용할 도메인 목록
ALLOWED_DOMAINS = ['rx.iptime.org', 'localhost', '127.0.0.1']
# 추가 허용 도메인이 있다면 여기에 넣으세요

# IP 주소 패턴 정규식
IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


# 접근 제한 미들웨어
@app.before_request
def check_host():
    # Host 헤더에서 호스트 정보 추출
    host = request.host.split(':')[0]  # 포트 번호 제외

    # 로컬호스트와 127.0.0.1은 항상 허용
    if host in ['localhost', '127.0.0.1']:
        return None

    # 허용된 도메인 검사
    if host in ALLOWED_DOMAINS:
        return None

    # IP 패턴 확인 (IP로 직접 접근하는 경우)
    if IP_PATTERN.match(host):
        logger.warning(f"IP 주소 접근 감지: {host}")
        # Google로 리다이렉트
        return redirect("https://www.google.com")

    # 기타 도메인은 허용 목록에 있는지 확인
    if host not in ALLOWED_DOMAINS:
        logger.warning(f"알 수 없는 도메인 접근 감지: {host}")
        # 같은 방식으로 처리
        return redirect("https://www.google.com")


# 허용된 파일 확장자 확인
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# 모델 로드
try:
    logger.info("모델 초기화 시작...")
    # 개별 모델 로드 시도
    try:
        vi_model = ViModel()
        logger.info(f"ViModel 로드 성공: {vi_model.__class__.__name__}")
    except Exception as e:
        logger.error(f"ViModel 로드 실패: {str(e)}")
        vi_model = None
    
    try:
        swin_model = SwinModel()
        logger.info(f"SwinModel 로드 성공: {swin_model.__class__.__name__}")
    except Exception as e:
        logger.error(f"SwinModel 로드 실패: {str(e)}")
        swin_model = None
    
    # 사용 가능한 모델만 등록
    models = {}
    if vi_model is not None:
        models['vi'] = vi_model
        logger.info("vi 모델이 딕셔너리에 추가되었습니다.")
    
    if swin_model is not None:
        models['swin'] = swin_model
        logger.info("swin 모델이 딕셔너리에 추가되었습니다.")
    
    # 사용 가능한 모델 확인
    logger.info(f"사용 가능한 모델 키: {list(models.keys())}")
    
    # 기본 모델 설정
    if 'vi' in models:
        default_model = 'vi'
    elif 'swin' in models:
        default_model = 'swin'
    else:
        raise ValueError("사용 가능한 모델이 없습니다.")
    
    logger.info(f"기본 모델 설정: {default_model}")
    
except Exception as e:
    logger.error(f"모델 초기화 오류: {str(e)}")
    # 최소한 ViModel은 초기화 시도
    vi_model = ViModel()
    models = {'vi': vi_model}
    default_model = 'vi'
    logger.info("기본 ViModel만 로드되었습니다.")


# 메인 페이지
@app.route('/')
def index():
    return render_template('index.html')

# 관리자 페이지
@app.route('/admin')
def admin():
    return render_template('admin.html')

# OpenAI API 키 설정 API
@app.route('/api/settings/openai', methods=['POST'])
def update_openai_settings():
    if request.method == 'POST':
        try:
            data = request.json
            if not data or 'api_key' not in data:
                return jsonify({'error': 'API 키가 필요합니다'}), 400

            api_key = data['api_key']
            # API 키 유효성 검사 (간단한 형식 검사만)
            if not api_key.startswith('sk-') and api_key != '':
                return jsonify({'error': 'OpenAI API 키 형식이 올바르지 않습니다'}), 400

            # 세션과 앱 설정에 API 키 저장
            session['openai_api_key'] = api_key
            app.config['OPENAI_API_KEY'] = api_key

            logger.info("OpenAI API 키가 업데이트되었습니다.")
            return jsonify({'success': True, 'message': 'API 키가 설정되었습니다'})
        except Exception as e:
            logger.error(f"OpenAI API 키 설정 중 오류: {str(e)}")
            return jsonify({'error': str(e)}), 500

# 현재 OpenAI API 키 상태 확인 API
@app.route('/api/settings/openai', methods=['GET'])
def get_openai_settings():
    try:
        # 세션 또는 앱 설정에서 API 키 가져오기
        api_key = session.get('openai_api_key', app.config.get('OPENAI_API_KEY', ''))
        
        # API 키가 설정되어 있는지만 확인 (보안상 키 자체는 반환하지 않음)
        is_set = bool(api_key)
        
        return jsonify({
            'success': True,
            'api_key_set': is_set
        })
    except Exception as e:
        logger.error(f"OpenAI API 키 상태 확인 중 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500


# 404 에러 핸들러 - 커스텀 404 페이지
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# OpenAI API를 사용하여 병변 설명 생성
def generate_openai_description(image_path, diagnoses, model_used):
    try:
        # API 키 확인
        api_key = os.environ.get('OPENAI_API_KEY', '')
        if not api_key:
            logger.warning("OpenAI API 키가 설정되지 않았습니다. 기본 설명을 반환합니다.")
            return "이 피부 병변에 대한 자세한 설명을 생성하기 위해 OpenAI API 키가 필요합니다. 관리자에게 문의하세요."

        # 이미지를 base64로 인코딩
        with open(image_path, "rb") as image_file:
            base64_image = base64.b64encode(image_file.read()).decode('utf-8')

        # 진단 결과 상위 3개 추출
        top_diagnoses = diagnoses[:min(3, len(diagnoses))]
        diagnoses_text = ", ".join([f"{d['diagnosis']} ({int(d['probability']*100)}%)" for d in top_diagnoses])
        
        # API 요청 헤더
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }

        # 최신 모델로 업데이트 (gpt-4-vision-preview가 더 이상 지원되지 않음)
        # 최신 버전인 gpt-4o 모델 사용
        model_name = "gpt-4o"
        
        # 프롬프트 수정 - 더 일반적인 요청으로 변경
        system_prompt = "당신은 의학적 설명을 제공하는 유용한 도우미입니다. 이미지와 텍스트 데이터를 바탕으로 교육적이고 유용한 정보를 제공해 주세요."
        user_prompt = f"""
이 이미지는 피부 질환의 예시입니다. 이미지에 대한 AI 분석 결과 가능성 있는 진단으로 다음이 제시되었습니다: {diagnoses_text}

이 이미지에 보이는 피부 상태에 대해 다음 사항을 포함하여 간략하게 교육적인 설명을 제공해주세요:
1. 이미지를 형태와 병변 크기등 이미지가 해당 변병으로 보이는 이유를 상세 안내
2. 이런 피부 상태의 일반적인 원인
3. 이러한 상태에 대한 일반적인 접근 방식 
4. 언제 의사를 방문해야 하는지에 대한 안내

의학적으로 정확하되 이해하기 쉬운 용어를 사용해주세요. 이 설명은 교육적 목적으로만 사용되며, 의학적 조언을 대체하지 않음을 명시해주세요.
"""
        
        # API 요청 본문
        payload = {
            "model": model_name,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": user_prompt
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{base64_image}"
                            }
                        }
                    ]
                }
            ],
            "max_tokens": 800,
            "temperature": 0.7
        }

        # 로그에 요청 정보 추가
        logger.info(f"OpenAI API 요청: 모델={payload['model']}, 이미지 크기={len(base64_image)}, 진단={diagnoses_text}")
        
        # 최신 OpenAI API 엔드포인트
        api_url = "https://api.openai.com/v1/chat/completions"
        
        # API 요청 보내기
        response = requests.post(api_url, headers=headers, json=payload)
        
        # 응답 상태 로깅
        logger.info(f"OpenAI API 응답 상태 코드: {response.status_code}")
        
        # 오류 응답 확인
        if response.status_code != 200:
            logger.error(f"OpenAI API 오류: {response.status_code} {response.text}")
            raise Exception(f"OpenAI API 오류: {response.status_code} {response.text}")
            
        response.raise_for_status()  # HTTP 오류 발생 시 예외 발생
        
        # 응답에서 텍스트 추출
        response_data = response.json()
        
        # 응답 구조 확인 로깅
        logger.info(f"OpenAI API 응답 키: {', '.join(response_data.keys())}")
        
        # 응답 구조에 따라 다른 처리
        if "choices" in response_data and len(response_data["choices"]) > 0:
            # 표준 응답 형식
            if "message" in response_data["choices"][0] and "content" in response_data["choices"][0]["message"]:
                openai_description = response_data["choices"][0]["message"]["content"].strip()
            # 대체 응답 형식 (모델에 따라 다를 수 있음)
            elif "text" in response_data["choices"][0]:
                openai_description = response_data["choices"][0]["text"].strip()
            else:
                logger.error(f"알 수 없는 OpenAI API 응답 형식: {response_data}")
                raise Exception("알 수 없는 OpenAI API 응답 형식")
        else:
            logger.error(f"OpenAI API 응답에 선택지가 없음: {response_data}")
            raise Exception("OpenAI API 응답에 선택지가 없음")
        
        # "I'm sorry, I can't assist with that..." 응답 체크
        if openai_description.lower().startswith("i'm sorry") or openai_description.lower().startswith("i apologize"):
            logger.warning(f"OpenAI에서 거부 응답 받음: {openai_description}")
            # 백업 설명 생성
            if diagnoses and len(diagnoses) > 0:
                top_diagnosis = diagnoses[0]['diagnosis']
                default_description = f"""
{top_diagnosis}는 피부에 나타나는 상태입니다. 이 유형의 피부 상태는 전문적인 진단과 치료가 필요할 수 있습니다.

일반적으로 이러한 피부 상태는 다양한 원인에 의해 발생할 수 있으며, 적절한 치료를 위해서는 피부과 전문의의 정확한 진단이 중요합니다.

이 설명은 참고용이며, 정확한 진단 및 치료 방법은 반드시 전문 의료인과 상담하시기 바랍니다.
"""
                return default_description
        
        # 디버그용 로깅 추가
        logger.info("OpenAI에서 병변 설명 생성 완료")
        logger.info(f"생성된 설명: {openai_description[:100]}...")  # 처음 100자만 로깅
        
        return openai_description
        
    except Exception as e:
        logger.error(f"OpenAI 병변 설명 생성 중 오류: {str(e)}")
        # 스택 트레이스 로깅
        import traceback
        logger.error(traceback.format_exc())
        
        # 기본 설명 반환
        if diagnoses and len(diagnoses) > 0:
            top_diagnosis = diagnoses[0]['diagnosis']
            return f"""{top_diagnosis}로 의심되는 피부 상태입니다.

이러한 피부 상태는 다양한 원인에 의해 발생할 수 있으며, 적절한 관리가 필요할 수 있습니다.

정확한 진단과 치료 방법은 반드시 피부과 전문의와 상담하시기 바랍니다."""
        else:
            return """이 피부 상태에 대한 정확한 분석을 위해서는 피부과 전문의와 상담이 필요합니다.

피부 상태는 개인마다 다르게 나타날 수 있으며, 적절한 진단과 치료를 위해서는 전문가의 검진이 중요합니다.

이 설명은 참고용이며, 의학적 조언을 대체할 수 없습니다."""

# 이미지 업로드 및 분석 API
@app.route('/api/analyze', methods=['POST'])
def analyze_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # 모델 선택 처리 (없으면 기본 모델 사용)
    model_type = request.form.get('model', default_model)
    logger.info(f"요청된 모델 유형: {model_type}")
    
    if model_type not in models:
        logger.warning(f"알 수 없는 모델 유형: {model_type}, 기본 모델로 대체")
        model_type = default_model
    
    # 선택된 모델 가져오기
    model = models[model_type]
    logger.info(f"선택된 모델: {model_type}, 클래스: {model.__class__.__name__}")

    if file and allowed_file(file.filename):
        # 안전한 파일명으로 변경
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        try:
            logger.info(f"이미지 분석 시작: {unique_filename}, 모델: {model_type}")
            # 이미지 전처리
            processed_image = model.preprocess_image(file_path)

            # 진단명 예측
            diagnoses = model.predict(processed_image)
            
            # 기본 병변 설명 생성
            default_description = model.generate_description(processed_image)
            logger.info(f"기본 설명 생성됨: {default_description[:50]}...")
            
            # OpenAI 기반 설명 생성 시도
            openai_description = generate_openai_description(file_path, diagnoses, model_type)
            
            # 최종 설명 선택 (OpenAI 설명이 있으면 사용, 없으면 기본 설명 사용)
            description = openai_description if openai_description else default_description
            
            # OpenAI 설명 사용 여부 표시
            used_openai = openai_description is not None
            
            logger.info(f"최종 설명 선택: {'OpenAI' if used_openai else '기본'} 설명 (길이: {len(description)})")

            # 이미지 URL 생성
            image_url = url_for('static', filename=f'uploads/{unique_filename}', _external=True)
            
            # 결과 JSON 생성
            result = {
                'image_url': image_url,
                'description': description,
                'diagnoses': diagnoses,
                'model_used': model_type,
                'used_openai': used_openai
            }
            
            # 결과 키 확인 로깅
            logger.info(f"응답 JSON 키: {', '.join(result.keys())}")
            logger.info(f"설명 타입: {type(description).__name__}, 설명 길이: {len(description)}")

            # 분석 로그 저장
            try:
                # IP 주소 추출
                ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
                diagnoses_json = json.dumps(diagnoses)
                
                # 데이터베이스에 저장
                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                
                cursor.execute(
                    'INSERT INTO analysis_log (image_path, model, ip_address, diagnoses) VALUES (?, ?, ?, ?)',
                    (image_url, model_type, ip_address, diagnoses_json)
                )
                
                conn.commit()
                conn.close()
                logger.info(f"분석 로그 저장 성공: {image_url}, 모델: {model_type}, IP: {ip_address}")
            except Exception as e:
                logger.error(f"분석 로그 저장 오류: {str(e)}")
                # 로그 저장 실패해도 결과는 반환
            
            logger.info(f"이미지 분석 완료: {len(diagnoses)}개 진단 결과, 모델: {model_type}")
            
            # 최종 JSON 응답
            response = jsonify(result)
            
            # CORS 헤더 추가 (필요한 경우)
            response.headers.add('Access-Control-Allow-Origin', '*')
            
            return response

        except Exception as e:
            logger.error(f"이미지 분석 오류: {str(e)}")
            # 상세 오류 스택트레이스 로깅
            import traceback
            logger.error(traceback.format_exc())
            return jsonify({'error': str(e)}), 500

    return jsonify({'error': 'File type not allowed'}), 400


# 좋아요/싫어요 API
@app.route('/api/feedback', methods=['POST'])
def save_feedback():
    try:
        logger.info(f"피드백 API 호출 - 요청 데이터: {request.json}")
        
        data = request.json
        
        if not data:
            logger.error("요청 바디가 없거나 JSON 형식이 아닙니다.")
            return jsonify({'error': '요청 바디가 없거나 JSON 형식이 아닙니다.'}), 400
        
        if 'image_path' not in data or 'score' not in data:
            logger.error(f"필수 데이터 누락: {data}")
            return jsonify({'error': '필수 데이터가 누락되었습니다.'}), 400
        
        # 데이터 추출
        image_path = data['image_path']
        score = data['score']  # 좋아요: 1, 싫어요: -1
        diagnoses = data.get('diagnoses', [])  # 진단 정보 (배열)
        model = data.get('model', '')  # 모델 정보

        # 진단 정보를 JSON 문자열로 변환
        diagnoses_json = json.dumps(diagnoses)
        
        # IP 주소 추출 (X-Forwarded-For 헤더가 있으면 사용, 없으면 원격 주소 사용)
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        logger.info(f"피드백 데이터: {image_path}, 점수: {score}, IP: {ip_address}, 진단 수: {len(diagnoses)}")
        
        # 데이터베이스에 저장
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute(
                'INSERT INTO feedback (image_path, ip_address, score, diagnoses, model) VALUES (?, ?, ?, ?, ?)',
                (image_path, ip_address, score, diagnoses_json, model)
            )
            
            conn.commit()
            conn.close()
            
            logger.info(f"피드백 저장 성공: {image_path}, 점수: {score}, IP: {ip_address}")
            return jsonify({'success': True, 'message': '피드백이 저장되었습니다.'})
        
        except Exception as e:
            logger.error(f"데이터베이스 저장 오류: {str(e)}")
            return jsonify({'error': f'데이터베이스 저장 오류: {str(e)}'}), 500
    
    except Exception as e:
        logger.error(f"피드백 저장 처리 중 예외 발생: {str(e)}")
        return jsonify({'error': str(e)}), 500

# 관리자용 피드백 목록 API
@app.route('/api/admin/feedback', methods=['GET'])
def get_feedback():
    try:
        # 필터 파라미터 가져오기
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        score_filter = request.args.get('score', 'all')
        ip_filter = request.args.get('ip', '')
        model = request.args.get('model', '')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        
        # 페이지네이션 계산
        offset = (page - 1) * per_page
        
        # 쿼리 구성
        query = 'SELECT * FROM feedback WHERE 1=1'
        params = []
        
        if start_date:
            query += ' AND date(created_at) >= ?'
            params.append(start_date)
        
        if end_date:
            query += ' AND date(created_at) <= ?'
            params.append(end_date)
        
        if score_filter == 'positive':
            query += ' AND score > 0'
        elif score_filter == 'negative':
            query += ' AND score < 0'
        
        if ip_filter:
            query += ' AND ip_address LIKE ?'
            params.append(f'%{ip_filter}%')

        if model:
            query += ' AND model = ?'
            params.append(model)
        
        # 카운트 쿼리
        count_query = query.replace('SELECT *', 'SELECT COUNT(*)')
        
        # 정렬 및 페이지네이션
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, offset])
        
        # 데이터베이스 연결 및 쿼리 실행
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row  # 딕셔너리 형태로 결과 반환
        cursor = conn.cursor()
        
        # 전체 결과 수 가져오기
        cursor.execute(count_query, params[:-2] if len(params) >= 2 else params)
        total_count = cursor.fetchone()[0]
        
        # 피드백 데이터 가져오기
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        # 결과 변환
        feedback_data = []
        for row in rows:
            row_dict = dict(row)
            
            # diagnoses 필드가 없을 수 있으므로 안전하게 처리
            diagnoses = []
            if 'diagnoses' in row_dict and row_dict['diagnoses']:
                try:
                    diagnoses = json.loads(row_dict['diagnoses'])
                except json.JSONDecodeError:
                    logger.error(f"JSON 파싱 오류: {row_dict.get('diagnoses', 'None')}")
            
            feedback_item = {
                'id': row_dict['id'],
                'image_path': row_dict['image_path'],
                'ip_address': row_dict['ip_address'],
                'score': row_dict['score'],
                'model': row_dict['model'],
                'diagnoses': diagnoses,
                'created_at': row_dict['created_at']
            }
            
            feedback_data.append(feedback_item)
        
        # 총 페이지 수 계산
        total_pages = (total_count + per_page - 1) // per_page
        
        conn.close()
        
        return jsonify({
            'feedback': feedback_data,
            'pagination': {
                'current_page': page,
                'per_page': per_page,
                'total_count': total_count,
                'total_pages': total_pages
            }
        })
    
    except Exception as e:
        logger.error(f"피드백 데이터 조회 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500


# 관리자용 피드백 통계 API
@app.route('/api/admin/statistics', methods=['GET'])
def get_statistics():
    try:
        logger.info("통계 API 호출")
        
        # 필터 파라미터 가져오기
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        ip_filter = request.args.get('ip', '')
        
        logger.info(f"통계 필터: start_date={start_date}, end_date={end_date}, ip={ip_filter}")
        
        # 쿼리 구성
        base_query = 'FROM feedback WHERE 1=1'
        params = []
        
        if start_date:
            base_query += ' AND date(created_at) >= ?'
            params.append(start_date)
        
        if end_date:
            base_query += ' AND date(created_at) <= ?'
            params.append(end_date)
        
        if ip_filter:
            base_query += ' AND ip_address LIKE ?'
            params.append(f'%{ip_filter}%')
        
        # 데이터베이스 연결
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # 총 피드백 수 가져오기
        cursor.execute(f"SELECT COUNT(*) {base_query}", params)
        total_feedback = cursor.fetchone()[0]
        
        # 좋아요 수 가져오기
        cursor.execute(f"SELECT COUNT(*) {base_query} AND score > 0", params)
        total_likes = cursor.fetchone()[0]
        
        # 싫어요 수 가져오기
        cursor.execute(f"SELECT COUNT(*) {base_query} AND score < 0", params)
        total_dislikes = cursor.fetchone()[0]
        
        conn.close()
        
        result = {
            'total_feedback': total_feedback,
            'total_likes': total_likes,
            'total_dislikes': total_dislikes
        }
        
        logger.info(f"통계 결과: {result}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"피드백 통계 조회 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500


# 관리자용 분석 로그 API
@app.route('/api/admin/analysis-log', methods=['GET'])
def get_analysis_log():
    try:
        # 필터 파라미터 가져오기
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        ip_filter = request.args.get('ip', '')
        model = request.args.get('model', '')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        
        # 페이지네이션 계산
        offset = (page - 1) * per_page
        
        # 쿼리 구성
        query = 'SELECT * FROM analysis_log WHERE 1=1'
        params = []
        
        if start_date:
            query += ' AND date(created_at) >= ?'
            params.append(start_date)
        
        if end_date:
            query += ' AND date(created_at) <= ?'
            params.append(end_date)
        
        if ip_filter:
            query += ' AND ip_address LIKE ?'
            params.append(f'%{ip_filter}%')

        if model:
            query += ' AND model = ?'
            params.append(model)
        
        # 카운트 쿼리
        count_query = query.replace('SELECT *', 'SELECT COUNT(*)')
        
        # 정렬 및 페이지네이션
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, offset])
        
        # 데이터베이스 연결 및 쿼리 실행
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row  # 딕셔너리 형태로 결과 반환
        cursor = conn.cursor()
        
        # 전체 결과 수 가져오기
        cursor.execute(count_query, params[:-2] if len(params) >= 2 else params)
        total_count = cursor.fetchone()[0]
        
        # 로그 데이터 가져오기
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        # 결과 변환
        log_data = []
        for row in rows:
            row_dict = dict(row)
            
            # diagnoses 필드가 없을 수 있으므로 안전하게 처리
            diagnoses = []
            if 'diagnoses' in row_dict and row_dict['diagnoses']:
                try:
                    diagnoses = json.loads(row_dict['diagnoses'])
                except json.JSONDecodeError:
                    logger.error(f"JSON 파싱 오류: {row_dict.get('diagnoses', 'None')}")
            
            log_item = {
                'id': row_dict['id'],
                'image_path': row_dict['image_path'],
                'ip_address': row_dict['ip_address'],
                'model': row_dict['model'],
                'diagnoses': diagnoses,
                'created_at': row_dict['created_at']
            }
            
            log_data.append(log_item)
        
        # 총 페이지 수 계산
        total_pages = (total_count + per_page - 1) // per_page
        
        conn.close()
        
        return jsonify({
            'logs': log_data,
            'pagination': {
                'current_page': page,
                'per_page': per_page,
                'total_count': total_count,
                'total_pages': total_pages
            }
        })
    
    except Exception as e:
        logger.error(f"분석 로그 데이터 조회 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500


# 관리자용 분석 로그 통계 API
@app.route('/api/admin/analysis-log/statistics', methods=['GET'])
def get_analysis_log_statistics():
    try:
        logger.info("분석 로그 통계 API 호출")
        
        # 필터 파라미터 가져오기
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        ip_filter = request.args.get('ip', '')
        model = request.args.get('model', '')
        
        logger.info(f"통계 필터: start_date={start_date}, end_date={end_date}, ip={ip_filter}, model={model}")
        
        # 쿼리 구성
        base_query = 'FROM analysis_log WHERE 1=1'
        params = []
        
        if start_date:
            base_query += ' AND date(created_at) >= ?'
            params.append(start_date)
        
        if end_date:
            base_query += ' AND date(created_at) <= ?'
            params.append(end_date)
        
        if ip_filter:
            base_query += ' AND ip_address LIKE ?'
            params.append(f'%{ip_filter}%')
            
        if model:
            base_query += ' AND model = ?'
            params.append(model)
        
        # 데이터베이스 연결
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # 총 로그 수 가져오기
        cursor.execute(f"SELECT COUNT(*) {base_query}", params)
        total_logs = cursor.fetchone()[0]
        
        # 모델별 사용 집계
        cursor.execute(f"SELECT model, COUNT(*) as count {base_query} GROUP BY model", params)
        model_counts = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        result = {
            'total_logs': total_logs,
            'model_counts': model_counts
        }
        
        logger.info(f"분석 로그 통계 결과: {result}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"분석 로그 통계 조회 오류: {str(e)}")
        return jsonify({'error': str(e)}), 500


# 관리자용 분석 로그 삭제 API
@app.route('/api/admin/analysis-log/delete', methods=['POST'])
def delete_analysis_log():
    try:
        data = request.json
        
        if not data or 'ids' not in data or not data['ids']:
            return jsonify({'error': '삭제할 ID가 누락되었습니다.'}), 400
        
        ids = data['ids']
        logger.info(f"분석 로그 삭제 요청 받음: {ids}")
        
        # 문자열로 들어온 경우 리스트로 변환
        if isinstance(ids, str):
            ids = [ids]
        
        # ID 목록이 비어있는지 확인
        if len(ids) == 0:
            return jsonify({'error': '삭제할 ID가 누락되었습니다.'}), 400
        
        # 데이터베이스에서 삭제
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # 쿼리에 사용할 플레이스홀더 생성 (?, ?, ?, ...)
            placeholders = ', '.join(['?' for _ in ids])
            
            # 삭제 쿼리 실행
            cursor.execute(f'DELETE FROM analysis_log WHERE id IN ({placeholders})', ids)
            
            # 영향 받은 행 수 확인
            affected_rows = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            logger.info(f"삭제 완료: {affected_rows}개 분석 로그 항목 삭제됨")
            
            return jsonify({
                'success': True,
                'message': f'{affected_rows}개 항목이 삭제되었습니다.',
                'affected_rows': affected_rows
            })
            
        except Exception as e:
            logger.error(f"데이터베이스 삭제 오류: {str(e)}")
            return jsonify({'error': f'데이터베이스 삭제 오류: {str(e)}'}), 500
    
    except Exception as e:
        logger.error(f"분석 로그 삭제 처리 중 예외 발생: {str(e)}")
        return jsonify({'error': str(e)}), 500


# 관리자용 피드백 삭제 API
@app.route('/api/admin/feedback/delete', methods=['POST'])
def delete_feedback():
    try:
        data = request.json
        
        if not data or 'ids' not in data or not data['ids']:
            return jsonify({'error': '삭제할 ID가 누락되었습니다.'}), 400
        
        ids = data['ids']
        logger.info(f"삭제 요청 받음: {ids}")
        
        # 문자열로 들어온 경우 리스트로 변환
        if isinstance(ids, str):
            ids = [ids]
        
        # ID 목록이 비어있는지 확인
        if len(ids) == 0:
            return jsonify({'error': '삭제할 ID가 누락되었습니다.'}), 400
        
        # 데이터베이스에서 삭제
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # 쿼리에 사용할 플레이스홀더 생성 (?, ?, ?, ...)
            placeholders = ', '.join(['?' for _ in ids])
            
            # 삭제 쿼리 실행
            cursor.execute(f'DELETE FROM feedback WHERE id IN ({placeholders})', ids)
            
            # 영향 받은 행 수 확인
            affected_rows = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            logger.info(f"삭제 완료: {affected_rows}개 항목 삭제됨")
            
            return jsonify({
                'success': True,
                'message': f'{affected_rows}개 항목이 삭제되었습니다.',
                'affected_rows': affected_rows
            })
            
        except Exception as e:
            logger.error(f"데이터베이스 삭제 오류: {str(e)}")
            return jsonify({'error': f'데이터베이스 삭제 오류: {str(e)}'}), 500
    
    except Exception as e:
        logger.error(f"피드백 삭제 처리 중 예외 발생: {str(e)}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    logger.info("DermScan 백엔드 서버를 시작합니다. (http://localhost:5000)")
    app.run(host='0.0.0.0', port=5000, debug=True)