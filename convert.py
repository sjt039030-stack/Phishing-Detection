import tensorflow as tf

# 1. Load your model
model = tf.keras.models.load_model("tabular_cnn_lstm_model.h5")

# 2. Create a concrete function with a fixed batch size of 1
# This replaces the 'None' in (None, 10, 1) with '1'
run_model = tf.function(lambda x: model(x))
concrete_func = run_model.get_concrete_function(
    tf.TensorSpec([1, 10, 1], model.inputs[0].dtype)
)

# 3. Create the converter from the concrete function
converter = tf.lite.TFLiteConverter.from_concrete_functions([concrete_func])

# 4. Enable the special flags for LSTM support
converter.target_spec.supported_ops = [
    tf.lite.OpsSet.TFLITE_BUILTINS, 
    tf.lite.OpsSet.SELECT_TF_OPS
]
converter._experimental_lower_tensor_list_ops = False

# 5. Convert and save
try:
    tflite_model = converter.convert()
    with open("tabular_cnn_lstm_model.tflite", "wb") as f:
        f.write(tflite_model)
    print("✅ SUCCESS! 'tabular_cnn_lstm_model.tflite' has been created.")
except Exception as e:
    print(f"❌ Conversion failed: {e}")